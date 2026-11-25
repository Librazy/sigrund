//! The renderer writes to the verified TTY. Terminal input never uses stdin.
use crate::approver::{
    Decision, Exchange, Frontend, Review, ReviewTarget, WarrantExpired, check_terminal_event,
    discard_confirmation_input, event, poll, quote, warrant_remaining,
};
use ratatui::{
    Frame, Terminal, TerminalOptions, Viewport,
    backend::CrosstermBackend,
    layout::Rect,
    style::{Color, Modifier, Style},
    text::{Line, Span},
    widgets::Paragraph,
};
use std::{
    cell::RefCell,
    fmt::Write as _,
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    time::{Duration, Instant, SystemTime},
};

const ENTER: &[u8] = b"\x1b[?1049h\x1b[?25l\x1b[?2004h";
const LEAVE: &[u8] = b"\x18\x1b[0m\x1b[?2004l\x1b[?1049l\x1b[?25h";
const SIGNING_ENDED: &[u8] = b"\r\nSigning ended\r\n";
const REFRESH: Duration = Duration::from_millis(100);
const OUTPUT_STALL: Duration = Duration::from_millis(250);
const ESCAPE_WAIT: Duration = Duration::from_millis(40);
const MIN_WIDTH: u16 = 40;
const MIN_HEIGHT: u16 = 9;
const BODY_TOP: u16 = 4;
const FOOTER_ROWS: u16 = 3;
const INVALID_WARRANT: &str = "Warrant expired or not yet valid";

type Renderer = Terminal<CrosstermBackend<FrameOutput>>;

#[derive(Clone, Default)]
struct FrameOutput(std::rc::Rc<RefCell<Vec<u8>>>);

impl Write for FrameOutput {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.borrow_mut().write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

pub(crate) struct Screen<'a> {
    tty: &'a File,
    original: Option<libc::termios>,
    mode: ScreenMode,
    renderer: Option<Renderer>,
    last_idle: Option<(Rect, bool, &'static str, bool)>,
    output: FrameOutput,
    input: Input,
    pending_byte: Option<u8>,
    discarding_input: bool,
    awaiting_signing_ack: bool,
    status: &'static str,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ScreenMode {
    Alternate,
    // A buffer switch can stop partway through its escape sequence.
    Switching,
    Signing,
}

struct ReviewExchange<'a> {
    broker: &'a Exchange<'a>,
    review: &'a Review,
}

impl ReviewExchange<'_> {
    fn warrant_left(&self) -> io::Result<Duration> {
        warrant_remaining(&self.review.csr, SystemTime::now())
            .ok_or_else(|| io::Error::other(WarrantExpired))
    }

    fn check(&self) -> io::Result<()> {
        self.broker.check()?;
        self.warrant_left()?;
        Ok(())
    }

    fn wait_terminal(&self, tty: &File, interest: i16, until: Instant) -> io::Result<()> {
        let expiry = Instant::now().checked_add(self.warrant_left()?);
        self.broker.wait_terminal(
            tty,
            interest,
            expiry.map_or(until, |expiry| until.min(expiry)),
        )
    }
}

impl<'a> Screen<'a> {
    pub(crate) fn new(tty: &'a File) -> Self {
        Self {
            tty,
            original: None,
            mode: ScreenMode::Alternate,
            renderer: None,
            last_idle: None,
            output: FrameOutput::default(),
            input: Input::default(),
            pending_byte: None,
            discarding_input: false,
            awaiting_signing_ack: false,
            status: "",
        }
    }

    fn size(&self) -> io::Result<Rect> {
        let mut size: libc::winsize = unsafe { std::mem::zeroed() };
        if unsafe { libc::ioctl(self.tty.as_raw_fd(), libc::TIOCGWINSZ, &mut size) } < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Rect::new(
            0,
            0,
            size.ws_col.clamp(1, 300),
            size.ws_row.clamp(1, 120),
        ))
    }

    fn enter(&mut self, exchange: Option<&ReviewExchange<'_>>) -> io::Result<()> {
        let mut raw = if let Some(original) = self.original {
            original
        } else {
            let mut original = unsafe { std::mem::zeroed() };
            if unsafe { libc::tcgetattr(self.tty.as_raw_fd(), &mut original) } < 0 {
                return Err(io::Error::last_os_error());
            }
            self.original = Some(original);
            original
        };
        unsafe { libc::cfmakeraw(&mut raw) };
        set_attributes(self.tty, &raw)?;
        discard_confirmation_input(self.tty)?;
        self.input = Input::default();
        self.pending_byte = None;
        self.discarding_input = false;
        match self.mode {
            ScreenMode::Alternate => {}
            ScreenMode::Switching => write_terminal(self.tty, LEAVE, exchange)?,
            ScreenMode::Signing => write_terminal(self.tty, SIGNING_ENDED, exchange)?,
        }
        self.mode = ScreenMode::Switching;
        write_terminal(self.tty, ENTER, exchange)?;
        self.mode = ScreenMode::Alternate;
        Ok(())
    }

    fn paint(
        &mut self,
        area: Rect,
        exchange: Option<&ReviewExchange<'_>>,
        draw: impl FnOnce(&mut Frame<'_>),
    ) -> io::Result<()> {
        self.last_idle = None;
        if self.original.is_none() || self.mode != ScreenMode::Alternate {
            self.enter(exchange)?;
        }
        if self.renderer.is_none() {
            let mut terminal = Terminal::with_options(
                CrosstermBackend::new(self.output.clone()),
                TerminalOptions {
                    viewport: Viewport::Fixed(area),
                },
            )?;
            terminal.clear()?;
            self.renderer = Some(terminal);
        }
        let terminal = self.renderer.as_mut().expect("active renderer");
        if terminal.get_frame().area() != area {
            terminal.resize(area)?;
        }
        terminal.draw(draw)?;
        let result = write_terminal(self.tty, &self.output.0.borrow(), exchange);
        self.output.0.borrow_mut().clear();
        if result.is_err() {
            self.renderer = None;
            let mut output = self.output.0.borrow_mut();
            output.clear();
            // Cancel a partial escape sequence and force a full redraw.
            output.push(0x18);
        }
        result
    }

    fn paint_idle(
        &mut self,
        connected: bool,
        exchange: Option<&ReviewExchange<'_>>,
    ) -> io::Result<()> {
        let area = self.size()?;
        let status = self.status;
        let awaiting_ack = self.awaiting_signing_ack;
        let view = (area, connected, status, awaiting_ack);
        if self.last_idle == Some(view)
            && self.renderer.is_some()
            && self.mode == ScreenMode::Alternate
        {
            return Ok(());
        }
        self.paint(area, exchange, |frame| {
            draw_idle(frame, connected, status, awaiting_ack);
        })?;
        self.last_idle = Some(view);
        Ok(())
    }

    fn paint_prompt(
        &mut self,
        area: Rect,
        exchange: Option<&ReviewExchange<'_>>,
        draw: impl FnOnce(&mut Frame<'_>),
    ) -> io::Result<()> {
        self.paint(area, exchange, draw)?;
        self.discard_keys(exchange)
    }

    fn read_byte(&mut self) -> io::Result<Option<u8>> {
        if let Some(byte) = self.pending_byte.take() {
            return Ok(Some(byte));
        }
        let mut byte = [0];
        let mut tty = self.tty;
        loop {
            return match tty.read(&mut byte) {
                Ok(0) => Err(io::Error::other("operator terminal lost")),
                Ok(_) => Ok(Some(byte[0])),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(None),
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => Err(error),
            };
        }
    }

    fn key(&mut self) -> io::Result<Option<Key>> {
        for _ in 0..256 {
            let byte = self.read_byte()?;
            if let Some(escape) = self.input.expire_escape() {
                self.pending_byte = byte;
                return Ok(Some(escape));
            }
            let Some(byte) = byte else {
                return Ok(None);
            };
            if let Some(key) = self.input.feed(byte) {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    fn discard_keys(&mut self, exchange: Option<&ReviewExchange<'_>>) -> io::Result<()> {
        // A paste may straddle a request or dialog boundary. Read through the
        // decoder so a previously read paste opener still suppresses its tail.
        self.discarding_input = true;
        loop {
            if let Some(exchange) = exchange {
                exchange.check()?;
            }
            for _ in 0..4096 {
                let Some(byte) = self.read_byte()? else {
                    self.input.expire_escape();
                    self.discarding_input = false;
                    return Ok(());
                };
                if self.input.feed(byte) == Some(Key::Interrupt) {
                    return Err(io::ErrorKind::Interrupted.into());
                }
            }
            // Outside a review, give the broker loop a chance to check for
            // signals and requests before discarding the next batch.
            if exchange.is_none() {
                return Ok(());
            }
        }
    }
    fn idle_input(&mut self, exchange: Option<&ReviewExchange<'_>>) -> io::Result<bool> {
        if self.discarding_input {
            self.discard_keys(exchange)?;
            if self.discarding_input {
                return Ok(false);
            }
        }
        match self.key()? {
            Some(Key::Interrupt) => Err(io::ErrorKind::Interrupted.into()),
            Some(Key::Resume) if self.awaiting_signing_ack => {
                self.discard_keys(exchange)?;
                self.awaiting_signing_ack = false;
                Ok(false)
            }
            Some(Key::Char(b'q')) if !self.awaiting_signing_ack => Ok(true),
            _ => Ok(false),
        }
    }

    fn review_request(&mut self, exchange: &ReviewExchange<'_>) -> io::Result<Decision> {
        // A new request may arrive before the operator has acknowledged an
        // interrupted passphrase prompt. Keep its review keys disabled too.
        while self.awaiting_signing_ack {
            exchange.check()?;
            self.paint_idle(true, Some(exchange))?;
            self.idle_input(Some(exchange))?;
            if self.awaiting_signing_ack {
                exchange.wait_terminal(self.tty, libc::POLLIN, Instant::now() + REFRESH)?;
            }
        }
        self.status = "";
        let review = exchange.review;
        let display = ReviewPages::new(review);
        let mut view = ReviewView::default();
        let mut previous_size = None;
        loop {
            exchange.check()?;
            let area = self.size()?;
            view.resize(&display.pages[view.tab], area);
            let remaining = exchange.warrant_left()?.min(
                exchange
                    .broker
                    .deadline
                    .saturating_duration_since(Instant::now()),
            );
            self.paint(area, Some(exchange), |frame| {
                view.draw(frame, review, remaining);
            })?;
            if previous_size.replace(area) != Some(area) || self.discarding_input {
                self.discard_keys(Some(exchange))?;
            }
            exchange.check()?;
            match self.key()? {
                Some(Key::Interrupt) => return Err(io::ErrorKind::Interrupted.into()),
                Some(key) if fits(area) => match view.handle(key) {
                    Interaction::Continue => {}
                    Interaction::Prompt => {
                        view.resize(&display.pages[view.tab], area);
                        self.paint_prompt(area, Some(exchange), |frame| {
                            view.draw(frame, review, remaining);
                        })?;
                    }
                    Interaction::Decide(decision) if self.size()? == area => return Ok(decision),
                    Interaction::Decide(_) => view.prompt = Prompt::Review,
                },
                _ => {}
            }
            if self.pending_byte.is_none() {
                let refresh = Instant::now() + REFRESH;
                let wake_at = match self.input {
                    Input::Escape(Some(deadline)) => deadline.min(refresh),
                    _ => refresh,
                };
                exchange.wait_terminal(self.tty, libc::POLLIN, wake_at)?;
            }
        }
    }
}

impl Drop for Screen<'_> {
    fn drop(&mut self) {
        if let Some(original) = self.original {
            let _ = write_terminal(
                self.tty,
                if self.mode == ScreenMode::Signing {
                    SIGNING_ENDED
                } else {
                    LEAVE
                },
                None,
            );
            let _ = discard_confirmation_input(self.tty);
            let _ = set_attributes(self.tty, &original);
        }
    }
}

impl Frontend for Screen<'_> {
    fn tty_events(&self) -> i16 {
        libc::POLLIN
    }

    fn idle(&mut self, connected: bool) -> io::Result<bool> {
        if connected
            && matches!(
                self.status,
                "Approval connection ended" | "Approval timed out"
            )
        {
            self.status = "";
        }
        self.paint_idle(connected, None)?;
        self.idle_input(None)
    }

    fn review(
        &mut self,
        _tty: &File,
        review: &Review,
        exchange: &Exchange<'_>,
    ) -> io::Result<Decision> {
        match self.review_request(&ReviewExchange {
            broker: exchange,
            review,
        }) {
            Err(error) if WarrantExpired::matches(&error) => Ok(Decision::InvalidWarrant),
            result => result,
        }
    }

    fn before_signing(&mut self, review: &Review, exchange: &Exchange<'_>) -> io::Result<()> {
        let exchange = ReviewExchange {
            broker: exchange,
            review,
        };
        exchange.check()?;
        let mut settings = self
            .original
            .ok_or_else(|| io::Error::other("review screen not active"))?;
        // OpenSSH may restore these settings before the TUI gets control back.
        // Keep echo off for the whole handoff, including a cancelled secret read.
        settings.c_lflag &= !(libc::ECHO | libc::ECHONL);
        set_attributes(self.tty, &settings)?;
        self.mode = ScreenMode::Switching;
        self.renderer = None;
        write_terminal(self.tty, LEAVE, Some(&exchange))?;
        self.mode = ScreenMode::Signing;
        // The primary buffer wraps complete fields and retains helper errors
        // in scrollback. OpenSSH owns both the cursor and input after this write.
        write_terminal(
            self.tty,
            signing_context(review).as_bytes(),
            Some(&exchange),
        )?;
        discard_confirmation_input(self.tty)
    }

    fn cancel_signing_on_warrant_expiry(&self) -> bool {
        true
    }

    fn signing_interrupted(&mut self) {
        self.awaiting_signing_ack = true;
    }

    fn warrant_invalid(&mut self) {
        self.status = INVALID_WARRANT;
    }

    fn decision_sent(&mut self) {
        if self.status != INVALID_WARRANT {
            self.status = "Decision sent";
        }
    }

    fn submission_interrupted(&mut self) {
        self.status = "Submission unconfirmed";
        let _ = self.paint_idle(false, None);
    }

    fn reconnecting(&mut self, _tty: &File, error: &io::Error) -> io::Result<()> {
        if !matches!(self.status, "Submission unconfirmed" | INVALID_WARRANT) {
            self.status = if error.kind() == io::ErrorKind::TimedOut {
                "Approval timed out"
            } else {
                "Approval connection ended"
            };
        }
        if self.mode != ScreenMode::Alternate {
            self.paint_idle(false, None)?;
        }
        if self.renderer.is_some() {
            self.discard_keys(None)?;
        }
        Ok(())
    }
}

fn set_attributes(tty: &File, attributes: &libc::termios) -> io::Result<()> {
    loop {
        if unsafe { libc::tcsetattr(tty.as_raw_fd(), libc::TCSANOW, attributes) } == 0 {
            return Ok(());
        }
        let error = io::Error::last_os_error();
        if error.kind() != io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

fn write_terminal(
    mut tty: &File,
    mut bytes: &[u8],
    exchange: Option<&ReviewExchange<'_>>,
) -> io::Result<()> {
    let mut stalled_at = Instant::now() + OUTPUT_STALL;
    while !bytes.is_empty() {
        if let Some(exchange) = exchange {
            exchange.check()?;
        }
        if Instant::now() >= stalled_at {
            return Err(io::Error::other("operator terminal output stalled"));
        }
        match tty.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => {
                bytes = &bytes[count..];
                stalled_at = Instant::now() + OUTPUT_STALL;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if let Some(exchange) = exchange {
                    exchange.wait_terminal(tty, libc::POLLOUT, stalled_at)?;
                } else {
                    let mut events = [event(tty.as_raw_fd(), libc::POLLOUT)];
                    poll(&mut events, Some(stalled_at))?;
                    check_terminal_event(events[0])?;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Key {
    Char(u8),
    Enter,
    Backspace,
    Escape,
    Up,
    Down,
    PageUp,
    PageDown,
    Home,
    End,
    Paste,
    Resume,
    Interrupt,
    Other,
}

#[derive(Default)]
enum Input {
    #[default]
    Ground,
    Escape(Option<Instant>),
    Csi {
        bytes: [u8; 3],
        length: usize,
    },
    Paste(usize),
}

impl Input {
    fn expire_escape(&mut self) -> Option<Key> {
        if matches!(self, Self::Escape(Some(deadline)) if Instant::now() >= *deadline) {
            // Report Escape once, but allow a delayed CSI or paste opener to finish.
            *self = Self::Escape(None);
            Some(Key::Escape)
        } else {
            None
        }
    }

    fn feed(&mut self, byte: u8) -> Option<Key> {
        // Raw-mode cancellation must work even if a paste never closes.
        if matches!(byte, 3 | 26 | 28) {
            return Some(Key::Interrupt);
        }
        match self {
            Self::Paste(matched) => {
                // Bracketed paste uses an in-band delimiter. If the terminal
                // forwards an end marker from the clipboard, later bytes can
                // be decoded as keystrokes. Approval assumes a trusted terminal
                // path that filters pasted control sequences.
                const END: &[u8] = b"\x1b[201~";
                if byte == END[*matched] {
                    *matched += 1;
                    if *matched == END.len() {
                        *self = Self::Ground;
                    }
                } else {
                    *matched = usize::from(byte == END[0]);
                }
                None
            }
            Self::Ground => match byte {
                27 => {
                    *self = Self::Escape(Some(Instant::now() + ESCAPE_WAIT));
                    None
                }
                b'\r' | b'\n' => Some(Key::Enter),
                8 | 127 => Some(Key::Backspace),
                18 => Some(Key::Resume),
                b' '..=b'~' => Some(Key::Char(byte)),
                _ => Some(Key::Other),
            },
            Self::Escape(deadline) => {
                let pending = deadline.is_some();
                if matches!(byte, b'[' | b'O') {
                    *self = Self::Csi {
                        bytes: [0; 3],
                        length: 0,
                    };
                    None
                } else if byte == 27 {
                    *self = Self::Escape(Some(Instant::now() + ESCAPE_WAIT));
                    pending.then_some(Key::Escape)
                } else {
                    *self = Self::Ground;
                    if pending {
                        Some(Key::Escape)
                    } else {
                        self.feed(byte)
                    }
                }
            }
            Self::Csi { .. } if byte == 27 => {
                *self = Self::Escape(Some(Instant::now() + ESCAPE_WAIT));
                None
            }
            Self::Csi { bytes, length } => {
                if (b'@'..=b'~').contains(&byte) {
                    let key = match (bytes.get(..*length), byte) {
                        (Some(b""), b'A') => Key::Up,
                        (Some(b""), b'B') => Key::Down,
                        (Some(b""), b'H') => Key::Home,
                        (Some(b""), b'F') => Key::End,
                        (Some(b"5"), b'~') => Key::PageUp,
                        (Some(b"6"), b'~') => Key::PageDown,
                        (Some(b"200"), b'~') => Key::Paste,
                        _ => Key::Other,
                    };
                    *self = if key == Key::Paste {
                        Self::Paste(0)
                    } else {
                        Self::Ground
                    };
                    Some(key)
                } else {
                    if let Some(slot) = bytes.get_mut(*length) {
                        *slot = byte;
                    }
                    *length = (*length + 1).min(bytes.len() + 1);
                    None
                }
            }
        }
    }
}

#[derive(Default)]
enum Prompt {
    #[default]
    Review,
    Approve(String),
    InvalidApproval,
    Reject,
    Quit,
}

enum Interaction {
    Continue,
    Prompt,
    Decide(Decision),
}

#[derive(Default)]
struct ReviewView<'a> {
    width: u16,
    page: usize,
    offset: usize,
    rows: Vec<(bool, &'a str, Style)>,
    prompt: Prompt,
    tab: usize,
}

impl<'a> ReviewView<'a> {
    fn resize(&mut self, display: &'a str, area: Rect) {
        if self.width != area.width {
            self.width = area.width;
            self.rows.clear();
            self.prompt = Prompt::Review;
        }
        if fits(area) && self.rows.is_empty() {
            let width = usize::from(area.width - 2);
            let tab = self.tab;
            self.rows = display
                .lines()
                .flat_map(|line| {
                    let style = field_style(line, tab);
                    (0..line.len().max(1)).step_by(width).map(move |start| {
                        (
                            start != 0,
                            &line[start..(start + width).min(line.len())],
                            style,
                        )
                    })
                })
                .collect();
        }
        let page = usize::from(area.height.saturating_sub(BODY_TOP + FOOTER_ROWS));
        if self.page != page {
            self.page = page;
            self.prompt = Prompt::Review;
        }
        self.offset = self.offset.min(self.max_offset());
    }

    fn max_offset(&self) -> usize {
        self.rows.len().saturating_sub(self.page)
    }

    fn handle(&mut self, key: Key) -> Interaction {
        match key {
            Key::Up => self.offset = self.offset.saturating_sub(1),
            Key::Down => self.offset = (self.offset + 1).min(self.max_offset()),
            Key::PageUp => self.offset = self.offset.saturating_sub(self.page),
            Key::PageDown => self.offset = (self.offset + self.page).min(self.max_offset()),
            Key::Home => self.offset = 0,
            Key::End => self.offset = self.max_offset(),
            Key::Escape => self.prompt = Prompt::Review,
            _ => match (&mut self.prompt, key) {
                (Prompt::Review, Key::Char(tab @ b'1'..=b'5')) => {
                    self.tab = usize::from(tab - b'1');
                    self.rows.clear();
                    self.offset = 0;
                }
                (Prompt::Review, Key::Char(b'a' | b'r' | b'q')) => {
                    self.tab = 0;
                    self.rows.clear();
                    self.offset = 0;
                    self.prompt = match key {
                        Key::Char(b'a') => Prompt::Approve(String::new()),
                        Key::Char(b'r') => Prompt::Reject,
                        _ => Prompt::Quit,
                    };
                    return Interaction::Prompt;
                }
                (Prompt::Approve(answer), Key::Char(byte)) if answer.len() < 3 => {
                    answer.push(char::from(byte));
                }
                (Prompt::Approve(answer), Key::Backspace) => {
                    answer.pop();
                }
                (Prompt::Approve(answer), Key::Enter) if answer == "yes" => {
                    return Interaction::Decide(Decision::Approve);
                }
                (Prompt::Approve(answer), Key::Enter) => answer.clear(),
                (Prompt::Approve(_), Key::Char(_) | Key::Other | Key::Paste | Key::Resume) => {
                    self.prompt = Prompt::InvalidApproval;
                }
                (Prompt::InvalidApproval, Key::Enter) => {
                    self.prompt = Prompt::Approve(String::new());
                }
                (Prompt::Reject, Key::Enter) => return Interaction::Decide(Decision::Reject),
                (Prompt::Quit, Key::Enter) => return Interaction::Decide(Decision::Quit),
                _ => {}
            },
        }
        Interaction::Continue
    }

    fn draw(&self, frame: &mut Frame<'_>, review: &Review, remaining: Duration) {
        let area = frame.area();
        line(
            frame,
            0,
            "sigrund-approve-tui | Connected",
            Style::default(),
        );
        if !fits(area) {
            line(
                frame,
                1,
                "Enlarge terminal to review (40x9)",
                Style::default(),
            );
            return;
        }
        line(
            frame,
            1,
            &format!(
                "{}  Time left: {}s",
                ["Review", "Arguments", "Environment", "Access", "Evidence"][self.tab],
                remaining.as_millis().div_ceil(1000)
            ),
            Style::default().fg(if remaining.as_secs() < 15 {
                Color::Yellow
            } else {
                Color::Cyan
            }),
        );
        let tabs = ["1 Review", "2 Args", "3 Env", "4 Access", "5 Evidence"]
            .into_iter()
            .enumerate()
            .map(|(index, label)| {
                Span::styled(
                    format!("{label} "),
                    if index == self.tab {
                        Style::default()
                            .fg(Color::Black)
                            .bg(Color::Cyan)
                            .add_modifier(Modifier::BOLD)
                    } else {
                        Style::default().fg(Color::Gray)
                    },
                )
            })
            .collect::<Vec<_>>();
        frame.render_widget(
            Paragraph::new(Line::from(tabs)),
            Rect::new(0, 2, area.width, 1),
        );
        let badge = request_badge(review, area.width);
        line(frame, 3, &badge.content, badge.style);
        for (index, (continued, text, style)) in self
            .rows
            .iter()
            .skip(self.offset)
            .take(self.page)
            .enumerate()
        {
            let marker = if *continued { "> " } else { "  " };
            line(
                frame,
                BODY_TOP + index as u16,
                &format!("{marker}{text}"),
                *style,
            );
        }
        let footer = area.height - FOOTER_ROWS;
        let end = (self.offset + self.page).min(self.rows.len());
        let location = format!("Lines {}-{end} of {}", self.offset + 1, self.rows.len());
        line(frame, footer, &location, Style::default());
        let style = Style::default().add_modifier(Modifier::BOLD);
        match &self.prompt {
            Prompt::Review => {
                line(
                    frame,
                    footer + 1,
                    "Arrows / PgUp / PgDn to scroll",
                    Style::default(),
                );
                line(frame, footer + 2, "a Approve   r Reject   q Quit", style);
            }
            Prompt::Approve(answer) => {
                line(frame, footer + 1, "Type yes + Enter; Esc cancels", style);
                line(frame, footer + 2, &format!("Approve: {answer}"), style);
            }
            Prompt::InvalidApproval => {
                line(frame, footer + 1, "Approval input invalid", style);
                line(frame, footer + 2, "Enter resets. Esc cancels.", style);
            }
            Prompt::Reject => {
                line(frame, footer + 1, "Reject this request?", style);
                line(frame, footer + 2, "Enter rejects; Esc cancels", style);
            }
            Prompt::Quit => {
                line(
                    frame,
                    footer + 1,
                    "Quitting interrupts this request.",
                    style,
                );
                line(frame, footer + 2, "Enter quits; Esc cancels", style);
            }
        }
    }
}

fn fits(area: Rect) -> bool {
    area.width >= MIN_WIDTH && area.height >= MIN_HEIGHT
}

fn line(frame: &mut Frame<'_>, row: u16, text: &str, style: Style) {
    if row < frame.area().height {
        frame.render_widget(
            Paragraph::new(text).style(style),
            Rect::new(0, row, frame.area().width, 1),
        );
    }
}

fn draw_idle(frame: &mut Frame<'_>, connected: bool, status: &str, awaiting_ack: bool) {
    let connection = if connected {
        "Connected"
    } else {
        "Reconnecting"
    };
    line(
        frame,
        0,
        &format!("sigrund-approve-tui | {connection}"),
        Style::default(),
    );
    line(frame, 1, status, Style::default());
    if awaiting_ack {
        line(
            frame,
            2,
            "Signing interrupted. Stop typing.",
            Style::default(),
        );
        line(frame, 3, "Ctrl+R resumes input", Style::default());
        return;
    }
    if connected {
        line(frame, 2, "Waiting for a request", Style::default());
    }
    line(frame, 3, "q Quit", Style::default());
}

fn full_root_notice(review: &Review) -> Option<&'static str> {
    if !review.full_host_root {
        return None;
    }
    match review.target {
        ReviewTarget::Host => Some("[HOST] FULL HOST ROOT AUTHORITY"),
        ReviewTarget::NamespaceExecution | ReviewTarget::NamespaceAdmin => {
            Some("[NAMESPACE] FULL HOST ROOT AUTHORITY")
        }
        ReviewTarget::NamespaceReview => None,
    }
}

fn signing_context(review: &Review) -> String {
    let target = full_root_notice(review).unwrap_or(match review.target {
        ReviewTarget::NamespaceReview => "Namespace review (execution disabled)",
        ReviewTarget::Host => "Host",
        ReviewTarget::NamespaceExecution => "Namespace execution",
        ReviewTarget::NamespaceAdmin => "Administrative namespace execution",
    });
    format!(
        "\r\nsigrund-approve-tui | Signing\r\n{target}\r\nRequest {}\r\nCommand {}\r\nSigner {}\r\nFollow the OpenSSH prompt below\r\n",
        quote(&review.exec_id),
        quote(&review.csr.warrant().command.executable_path),
        quote(&review.signer_id),
    )
}

/// Pages are built only from the exact CSR and its verified private review.
/// Request strings always pass through quote(), keeping wrapping ASCII-only
/// and preserving argument/environment boundaries without terminal controls.
struct ReviewPages {
    pages: [String; 5],
}

fn request_badge(review: &Review, width: u16) -> Span<'static> {
    let style = Style::default().add_modifier(Modifier::BOLD);
    if let Some(notice) = full_root_notice(review) {
        return Span::styled(notice, style.fg(Color::Red));
    }
    let (place, color) = match review.target {
        ReviewTarget::NamespaceReview => ("[NS REVIEW ONLY]", Color::Yellow),
        ReviewTarget::Host => ("[HOST]", Color::Cyan),
        ReviewTarget::NamespaceExecution => ("[NAMESPACE]", Color::Magenta),
        ReviewTarget::NamespaceAdmin => ("[NS ADMIN]", Color::Yellow),
    };
    let w = review.csr.warrant();
    let credentials = format!(
        "{place} UID {} / GID {}",
        w.execution_context.target_uid, w.execution_context.target_gid
    );
    let label = if credentials.len() <= usize::from(width) {
        credentials
    } else {
        format!("{place} (IDs in Access)")
    };
    Span::styled(label, style.fg(color))
}

fn field_style(text: &str, tab: usize) -> Style {
    let style = Style::default();
    // In the human-readable pages only formatter-owned labels can start a
    // logical line. Every request value is quoted and stays on that line.
    if tab == 4 {
        style
    } else if text.starts_with("! ") {
        style.fg(Color::Yellow).add_modifier(Modifier::BOLD)
    } else if text.starts_with("Executable ") || text.starts_with("Argv preview ") {
        style.fg(Color::Cyan).add_modifier(Modifier::BOLD)
    } else if text.starts_with("Target ") || text.starts_with("Run as ") {
        style.fg(Color::Magenta).add_modifier(Modifier::BOLD)
    } else if text.starts_with("[+] ") {
        style.fg(Color::Green)
    } else {
        style
    }
}

fn target_selection(review: &Review) -> String {
    use sigrund_core::host::Selector;
    match &review.csr.warrant().intent.target {
        Selector::Host {} => "Host".into(),
        Selector::Self_ {} => "Requester's namespaces (self)".into(),
        Selector::Registered { id } => format!("Registered namespace {}", quote(id)),
        Selector::Process { pid, .. } => format!("Process namespaces (daemon PID {pid})"),
    }
}

fn display_value(value: &serde_json::Value) -> String {
    match value {
        serde_json::Value::String(text) => quote(text),
        serde_json::Value::Array(items) => format!(
            "[{}]",
            items
                .iter()
                .map(display_value)
                .collect::<Vec<_>>()
                .join(", ")
        ),
        serde_json::Value::Object(items) => items
            .iter()
            .map(|(key, value)| format!("{}: {}", quote(key), display_value(value)))
            .collect::<Vec<_>>()
            .join("; "),
        _ => value.to_string(),
    }
}

impl ReviewPages {
    fn new(review: &Review) -> Self {
        let w = review.csr.warrant();
        let command = &w.command;
        let context = &w.execution_context;
        let mut summary = format!("Executable {}\n", quote(&command.executable_path));
        // A bounded preview keeps a 64 KiB argv from burying the destination.
        // Page 2 retains every byte, with indexed argument boundaries.
        let mut preview = String::new();
        let mut shown = 0;
        for arg in &command.argv {
            let arg = quote(arg);
            if preview.len() + arg.len() + 1 > 180 {
                break;
            }
            if !preview.is_empty() {
                preview.push(' ');
            }
            preview.push_str(&arg);
            shown += 1;
        }
        if shown == command.argv.len() {
            let _ = writeln!(summary, "Argv preview {preview}");
        } else {
            let _ = writeln!(summary, "Argv preview {preview} [partial preview]");
            let _ = writeln!(
                summary,
                "! {} argv entries omitted; 2 Args shows all",
                command.argv.len() - shown
            );
        }
        let _ = writeln!(summary, "Target {}", target_selection(review));
        if review.target == ReviewTarget::NamespaceReview {
            summary.push_str("! Review only; namespace execution is disabled\n");
        }
        let _ = writeln!(
            summary,
            "Environment {}",
            quote(&w.target_binding.description)
        );
        let _ = writeln!(
            summary,
            "Run as UID {} / GID {}",
            context.target_uid, context.target_gid
        );
        if let sigrund_core::host::Account::Name { name } = &w.intent.account {
            let _ = writeln!(summary, "Account {} (resolved in destination)", quote(name));
        }
        if let Some(host) = &review.host_credentials {
            let _ = writeln!(
                summary,
                "Mapped host UID {} / GID {}",
                host.host_uid, host.host_gid
            );
        }
        let _ = writeln!(
            summary,
            "Requester UID {} / GID {}",
            w.requester_uid, w.requester_gid
        );
        let _ = writeln!(summary, "Directory {}", quote(&command.cwd));
        let _ = writeln!(summary, "Profile {}", quote(&w.intent.security_profile));
        if context.target_uid == 0 {
            summary.push_str(if review.full_host_root {
                "! Full host root authority; all root powers\n"
            } else {
                "! UID 0 under the selected profile; inspect 4 Access\n"
            });
        }
        if !context.capabilities.is_empty() || !context.expected_capabilities().effective.is_empty()
        {
            let _ = writeln!(
                summary,
                "! Capabilities: {} requested / {} effective; 4 Access",
                context.capabilities.len(),
                context.expected_capabilities().effective.len()
            );
        }
        if !context.supplementary_gids.is_empty() {
            let _ = writeln!(
                summary,
                "Groups: {} supplementary; 4 Access shows all",
                context.supplementary_gids.len()
            );
        }
        let stdin = match command.stdin_policy.as_str() {
            "null" => "None (null input)",
            "sha256" => "Digest-bound finite input (hash in 4 Access)",
            "unrestricted_interactive" => "Unrestricted interactive input",
            other => other,
        };
        let _ = writeln!(summary, "Stdin {stdin}");
        let _ = writeln!(
            summary,
            "Environment values: {} exact, {} inherited; 3 Env",
            context.env_exact.len(),
            w.caller_env.len()
        );
        let _ = writeln!(summary, "Signer {}", quote(&review.signer_id));
        let origin = if w.request_origin == "client_full" {
            "Requester-prepared full CSR"
        } else {
            "Daemon-expanded thin intent"
        };
        let _ = writeln!(summary, "Source {origin}");
        let _ = writeln!(
            summary,
            "Grant {}; requested lifetime {}s",
            quote(&w.policy.mode),
            w.intent.policy.ttl_secs
        );
        summary.push_str("[+] Live evidence matched to this exact request\n5 Evidence shows complete verification records\n");
        // Selected executable/profile do not prove a command's behavior.
        if command.allow_interpreted_script {
            summary.push_str("! Interpreter/script execution is allowed\n");
        }

        let mut args = format!(
            "Executable {}\n{} argv entries (including argv[0])\nArguments are passed directly to the executable\n",
            quote(&command.executable_path),
            command.argv.len()
        );
        for (i, arg) in command.argv.iter().enumerate() {
            let _ = writeln!(args, "argv[{i}] = {}", quote(arg));
        }

        let mut env = format!(
            "Directory {}\nUmask {:03o}\n\nExact environment ({} values)\n",
            quote(&command.cwd),
            context.umask,
            context.env_exact.len()
        );
        for (key, value) in &context.env_exact {
            let _ = writeln!(env, "{} = {}", quote(key), quote(value));
        }
        let _ = writeln!(
            env,
            "\nAllowed caller environment ({} names)",
            context.caller_env_allowlist.len()
        );
        for key in &context.caller_env_allowlist {
            let value = w
                .caller_env
                .get(key)
                .map(|value| quote(value))
                .unwrap_or_else(|| "(absent)".into());
            let _ = writeln!(env, "{} = {value}", quote(key));
        }
        if context.caller_env_allowlist.is_empty() {
            env.push_str("No caller environment inherited\n");
        }

        let mut access = String::new();
        if review.target == ReviewTarget::NamespaceAdmin {
            access.push_str(
                "! Host privilege semantics apply\n\
                 ! Container containment is best effort\n",
            );
        }
        let _ = writeln!(
            access,
            "Target {}\nRun as UID {} / GID {}\nSupplementary GIDs {:?}\nProfile {}",
            target_selection(review),
            context.target_uid,
            context.target_gid,
            context.supplementary_gids,
            quote(&w.intent.security_profile)
        );
        if let Some(host) = &review.host_credentials {
            let _ = writeln!(
                access,
                "Mapped host UID {} / GID {}; groups {:?}",
                host.host_uid, host.host_gid, host.host_groups
            );
        }
        if review.full_host_root {
            access.push_str("! FULL HOST ROOT AUTHORITY\n");
        }
        access.push_str("\nRequested capabilities\n");
        if context.capabilities.is_empty() {
            access.push_str("None\n");
        }
        for cap in &context.capabilities {
            let _ = writeln!(access, "{}", quote(cap));
        }
        if let Some(caps) = &context.post_exec_capabilities {
            access.push_str("\nCapabilities after exec\n");
            for (name, values) in [
                ("Effective", &caps.effective),
                ("Permitted", &caps.permitted),
                ("Bounding", &caps.bounding),
                ("Inheritable", &caps.inheritable),
                ("Ambient", &caps.ambient),
            ] {
                let _ = writeln!(
                    access,
                    "{name}: {}",
                    if values.is_empty() {
                        "none".into()
                    } else {
                        values
                            .iter()
                            .map(|v| quote(v))
                            .collect::<Vec<_>>()
                            .join(", ")
                    }
                );
            }
        }
        access.push_str("\nVerified profile constraints\n");
        for (key, label) in [
            ("private_mount", "Private mount"),
            ("private_cgroup", "Private cgroup"),
            ("join_namespaces", "Joined namespaces"),
            ("no_new_privs", "No new privileges"),
            ("securebits", "Securebits"),
            ("lsm", "LSM contract"),
            ("workload", "Workload"),
            ("selinux", "SELinux"),
            ("apparmor", "AppArmor"),
            ("seccomp", "Seccomp contract"),
            ("memory_max", "Memory limit (bytes)"),
            ("memory_swap_max", "Swap limit (bytes)"),
            ("pids_max", "Process limit"),
            ("executable_model", "Executable trust"),
            ("verify_exec_stop", "Exec checkpoint"),
        ] {
            if let Some(value) = review.constraints.get(key) {
                let _ = writeln!(access, "{label}: {}", display_value(value));
            }
        }
        let _ = writeln!(
            access,
            "\nStdin {}\nTerminal {}\nUmask {:03o}",
            quote(&command.stdin_policy),
            quote(&command.tty_mode),
            context.umask
        );
        if let Some(hash) = &command.stdin_sha256 {
            let _ = writeln!(access, "Stdin SHA256 {}", quote(hash));
        }
        let evidence = format!(
            "Verified evidence for this request\nRequest {}\n\n{}",
            quote(&review.exec_id),
            review.details
        );
        Self {
            pages: [summary, args, env, access, evidence],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use std::os::fd::FromRawFd;

    fn fixture_review(change: impl FnOnce(&mut sigrund_core::warrant::Warrant)) -> Review {
        use sigrund_core::host::Record;
        let mut warrant = sigrund_core::warrant::Csr::parse(include_bytes!(
            "../../sigrund-core/tests/fixtures/v3-host/warrant.json"
        ))
        .unwrap()
        .warrant()
        .clone();
        change(&mut warrant);
        warrant.intent.command = warrant.command.requested();
        warrant.intent.execution_context.env_exact = warrant.execution_context.env_exact.clone();
        warrant.intent.execution_context.caller_env_allowlist =
            warrant.execution_context.caller_env_allowlist.clone();
        warrant.intent.caller_env = warrant.caller_env.clone();
        warrant.intent_sha256 = warrant.intent.sha256().unwrap();
        Review {
            exec_id: "0192d8f4-0000-7000-8000-000000000003".into(),
            signer_id: "operator".into(),
            csr: sigrund_core::warrant::Csr::new(warrant).unwrap(),
            details: "MACHINE_EVIDENCE_SENTINEL\ncsr[\"intent_sha256\"] = verified-digest\n".into(),
            target: ReviewTarget::Host,
            full_host_root: false,
            constraints: serde_json::json!({"private_mount":true,"no_new_privs":true,"memory_max":268435456}),
            host_credentials: None,
        }
    }

    #[test]
    fn review_prioritizes_command_and_destination_without_machine_records() {
        let review = fixture_review(|w| w.command.argv[0] = "custom-argv-zero".into());
        let pages = ReviewPages::new(&review);
        let summary = &pages.pages[0];
        assert!(
            summary.starts_with(
                "Executable \"/usr/bin/id\"\nArgv preview \"custom-argv-zero\" \"-u\""
            )
        );
        assert!(summary.contains("Run as UID 1001 / GID 1001"));
        assert!(summary.contains("Target Host"));
        assert!(summary.contains("Requester UID 1000 / GID 1000"));
        assert!(summary.lines().count() <= 17);
        assert!(!summary.contains("MACHINE_EVIDENCE_SENTINEL"));
        assert!(!summary.contains("intent_sha256"));
        assert!(pages.pages[4].contains("MACHINE_EVIDENCE_SENTINEL"));
        assert!(pages.pages[3].contains("Private mount: true"));
        assert_eq!(
            request_badge(&review, MIN_WIDTH).content,
            "[HOST] UID 1001 / GID 1001"
        );
    }

    #[test]
    fn large_argv_has_explicit_preview_limit_and_complete_separate_arguments() {
        let review = fixture_review(|w| {
            w.command
                .argv
                .extend((1..=20).map(|i| format!("field-{i}={}", "x".repeat(100))));
            w.command
                .argv
                .push("spaces, \"quotes\", café; $(id)".into());
        });
        let pages = ReviewPages::new(&review);
        assert!(pages.pages[0].contains("[partial preview]"));
        assert!(pages.pages[0].contains("argv entries omitted; 2 Args shows all"));
        assert!(pages.pages[0].len() < 1500);
        assert!(pages.pages[0].contains("Target Host"));
        for (i, arg) in review.csr.warrant().command.argv.iter().enumerate() {
            assert!(pages.pages[1].contains(&format!("argv[{i}] = {}", quote(arg))));
        }
        assert!(pages.pages.iter().all(|text| text.is_ascii()));
    }

    #[test]
    fn wrapped_rows_inherit_their_field_style() {
        let area = Rect::new(0, 0, 40, 24);
        let width = usize::from(area.width - 2);
        let mut review = fixture_review(|w| {
            for marker in ["[+] ", "! "] {
                let prefix = format!("argv[{}] = \"", w.command.argv.len());
                w.command.argv.push(format!(
                    "{}{marker}request data",
                    "x".repeat(width - prefix.len())
                ));
            }
        });
        review.target = ReviewTarget::NamespaceReview;
        let pages = ReviewPages::new(&review);
        let mut view = ReviewView::default();
        view.resize(&pages.pages[0], area);
        let warning = view
            .rows
            .iter()
            .position(|(_, text, _)| text.starts_with("! Review only"))
            .unwrap();
        assert_eq!(view.rows[warning].2.fg, Some(Color::Yellow));
        assert!(view.rows[warning + 1].0);
        assert_eq!(view.rows[warning + 1].2, view.rows[warning].2);

        view.handle(Key::Char(b'2'));
        view.resize(&pages.pages[1], area);
        for marker in ["[+] ", "! "] {
            let (continued, _, style) = view
                .rows
                .iter()
                .find(|(_, text, _)| text.starts_with(marker))
                .unwrap();
            assert!(continued);
            assert_eq!(*style, Style::default());
        }
    }

    #[test]
    fn overview_describes_each_valid_stdin_policy() {
        for (policy, description) in [
            ("null", "None (null input)"),
            ("sha256", "Digest-bound finite input"),
            ("unrestricted_interactive", "Unrestricted interactive input"),
        ] {
            let review = fixture_review(|w| {
                w.command.stdin_policy = policy.into();
                w.command.stdin_sha256 = (policy == "sha256").then(|| "0".repeat(64));
            });
            assert!(ReviewPages::new(&review).pages[0].contains(&format!("Stdin {description}")));
        }
    }

    #[test]
    fn signing_context_preserves_long_executable_and_signer() {
        let path = format!("/opt/{}tool", "directory/".repeat(48));
        let mut review = fixture_review(|w| {
            w.command.executable_path.clone_from(&path);
            w.command.argv[0].clone_from(&path);
        });
        review.signer_id = "long signer ".repeat(12);
        let output = signing_context(&review);
        assert!(output.contains(&format!("Command {}", quote(&path))));
        assert!(output.contains(&format!("Signer {}", quote(&review.signer_id))));
    }

    #[test]
    fn full_host_root_displays_execution_scope_during_confirmation_and_signing() {
        let mut review = fixture_review(|_| {});
        review.full_host_root = true;
        for (target, scope) in [
            (ReviewTarget::NamespaceAdmin, "[NAMESPACE]"),
            (ReviewTarget::Host, "[HOST]"),
        ] {
            review.target = target;
            let notice = format!("{scope} FULL HOST ROOT AUTHORITY");
            let pages = ReviewPages::new(&review);
            let area = Rect::new(0, 0, MIN_WIDTH, MIN_HEIGHT);
            let mut view = ReviewView::default();
            view.resize(&pages.pages[0], area);
            assert!(matches!(view.handle(Key::Char(b'a')), Interaction::Prompt));
            view.resize(&pages.pages[0], area);
            let confirmation = screen(area.width, area.height, |frame| {
                view.draw(frame, &review, Duration::ZERO)
            });
            assert_eq!(confirmation.lines().nth(3).unwrap().trim_end(), notice);
            assert!(confirmation.contains("Type yes + Enter"));
            assert!(signing_context(&review).contains(&notice));
        }
    }

    #[test]
    fn evidence_uses_terminal_default_foreground() {
        let mut review = fixture_review(|_| {});
        review.details = "! Literal evidence text".into();
        let pages = ReviewPages::new(&review);
        let mut view = ReviewView {
            tab: 4,
            ..Default::default()
        };
        view.resize(&pages.pages[4], Rect::new(0, 0, 80, 24));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| view.draw(frame, &review, Duration::from_secs(90)))
            .unwrap();
        let evidence = &terminal.backend().buffer()[(2, BODY_TOP + 3)];
        assert_eq!(evidence.symbol(), "!");
        assert_eq!(evidence.fg, Color::Reset);
        assert!(!evidence.modifier.contains(Modifier::BOLD));
    }

    #[test]
    fn environment_preserves_exact_values_and_allowed_caller_values() {
        let review = fixture_review(|w| {
            w.execution_context
                .env_exact
                .insert("TUI_TEST".into(), "spaces \"quoted\" café".into());
            w.execution_context
                .caller_env_allowlist
                .extend(["DISPLAY".into(), "TERM".into()]);
            w.caller_env.insert("TERM".into(), "xterm-256color".into());
        });
        let pages = ReviewPages::new(&review);
        assert!(pages.pages[0].contains("3 exact, 1 inherited; 3 Env"));
        assert!(pages.pages[2].contains(r#""TUI_TEST" = "spaces \"quoted\" caf\u{00E9}""#));
        assert!(pages.pages[2].contains(r#""TERM" = "xterm-256color""#));
        assert!(pages.pages[2].contains(r#""DISPLAY" = (absent)"#));
        assert!(pages.pages[2].contains("Umask 077"));
    }

    #[test]
    fn namespace_summary_uses_destination_and_composed_host_credentials() {
        use sigrund_core::namespace::Contract;
        let mut review = fixture_review(|_| {});
        review.csr = sigrund_core::warrant::Csr::parse(include_bytes!(
            "../../sigrund-core/tests/fixtures/namespace/warrant.json"
        ))
        .unwrap();
        let acquisition = sigrund_core::namespace::Acquisition::parse(include_bytes!(
            "../../sigrund-core/tests/fixtures/namespace/acquisition.json"
        ))
        .unwrap();
        let context = &review.csr.warrant().execution_context;
        let host = acquisition
            .compose_credentials(
                context.target_uid,
                context.target_gid,
                context.supplementary_gids.clone(),
            )
            .unwrap();
        review.host_credentials = Some(host.clone());
        review.target = ReviewTarget::NamespaceExecution;
        let pages = ReviewPages::new(&review);
        assert!(
            request_badge(&review, MIN_WIDTH)
                .content
                .starts_with("[NAMESPACE]")
        );
        assert!(pages.pages[0].contains("Requester's namespaces (self)"));
        assert!(pages.pages[0].contains(&format!(
            "Mapped host UID {} / GID {}",
            host.host_uid, host.host_gid
        )));
        assert!(!pages.pages[0].contains("FULL HOST ROOT"));
    }

    #[test]
    fn confirmation_returns_to_overview_and_navigation_cannot_confirm_it() {
        let mut review = fixture_review(|_| {});
        review.target = ReviewTarget::NamespaceReview;
        let pages = ReviewPages::new(&review);
        let area = Rect::new(0, 0, MIN_WIDTH, MIN_HEIGHT);
        let mut view = ReviewView::default();
        view.resize(&pages.pages[view.tab], area);
        view.handle(Key::Char(b'5'));
        view.resize(&pages.pages[view.tab], area);
        assert_eq!(view.tab, 4);
        assert!(
            view.rows
                .iter()
                .any(|(_, text, _)| text.contains("MACHINE_EVIDENCE"))
        );
        assert!(matches!(view.handle(Key::Char(b'a')), Interaction::Prompt));
        view.resize(&pages.pages[view.tab], area);
        assert_eq!(view.tab, 0);
        assert!(view.rows[0].1.starts_with("Executable "));
        let confirmation = screen(area.width, area.height, |frame| {
            view.draw(frame, &review, Duration::ZERO)
        });
        assert!(
            confirmation
                .lines()
                .nth(3)
                .unwrap()
                .starts_with("[NS REVIEW ONLY]")
        );
        assert!(confirmation.contains("Type yes + Enter"));
        for key in [Key::Char(b'2'), Key::Enter] {
            assert!(matches!(view.handle(key), Interaction::Continue));
        }
        assert_eq!(view.tab, 0);
        view.handle(Key::Escape);
        view.handle(Key::Char(b'2'));
        view.resize(&pages.pages[view.tab], area);
        assert_eq!(view.tab, 1);
        assert!(matches!(view.handle(Key::Enter), Interaction::Continue));
    }

    #[test]
    fn admin_namespace_warns_on_access_and_confirmation_with_no_requested_capabilities() {
        use sigrund_core::namespace::{Constraints, Contract};
        let mut review = fixture_review(|_| {});
        for bytes in [
            include_bytes!("../../sigrund-core/tests/fixtures/namespace/admin-constraints.json")
                .as_slice(),
            include_bytes!(
                "../../sigrund-core/tests/fixtures/namespace/admin-direct-constraints.json"
            )
            .as_slice(),
        ] {
            let constraints = Constraints::parse(bytes).unwrap();
            review.target = ReviewTarget::from(&constraints);
            review.constraints = serde_json::to_value(constraints).unwrap();
            let pages = ReviewPages::new(&review);
            let mut view = ReviewView {
                tab: 3,
                ..Default::default()
            };
            view.resize(&pages.pages[3], Rect::new(0, 0, MIN_WIDTH, MIN_HEIGHT));
            let access = screen(MIN_WIDTH, MIN_HEIGHT, |frame| {
                view.draw(frame, &review, Duration::ZERO)
            });
            assert!(access.contains("Host privilege semantics apply"));
            assert!(access.contains("Container containment is best effort"));
            assert!(pages.pages[3].contains("Requested capabilities\nNone"));
            assert!(!access.contains("FULL HOST ROOT AUTHORITY"));
            assert!(matches!(view.handle(Key::Char(b'a')), Interaction::Prompt));
            view.resize(&pages.pages[0], Rect::new(0, 0, MIN_WIDTH, MIN_HEIGHT));
            let confirmation = screen(MIN_WIDTH, MIN_HEIGHT, |frame| {
                view.draw(frame, &review, Duration::ZERO)
            });
            assert!(
                confirmation
                    .lines()
                    .nth(3)
                    .unwrap()
                    .starts_with("[NS ADMIN]"),
                "{confirmation}"
            );
            assert!(confirmation.contains("Type yes + Enter"));
            assert!(!confirmation.contains("FULL HOST ROOT AUTHORITY"));
        }
    }

    #[test]
    fn confirmation_badge_displays_both_credentials_in_full_or_omits_them() {
        let id = 1_000_000_000;
        let mut review = fixture_review(|w| {
            w.intent.account = sigrund_core::host::Account::Numeric {
                uid: id,
                gid: id,
                supplementary_gids: vec![],
            };
            w.execution_context.target_uid = id;
            w.execution_context.target_gid = id;
        });
        review.target = ReviewTarget::NamespaceExecution;
        let pages = ReviewPages::new(&review);
        for (width, expected) in [
            (MIN_WIDTH, "[NAMESPACE] (IDs in Access)"),
            (80, "[NAMESPACE] UID 1000000000 / GID 1000000000"),
        ] {
            let mut view = ReviewView::default();
            view.resize(&pages.pages[0], Rect::new(0, 0, width, MIN_HEIGHT));
            assert!(matches!(view.handle(Key::Char(b'a')), Interaction::Prompt));
            view.resize(&pages.pages[0], Rect::new(0, 0, width, MIN_HEIGHT));
            let confirmation = screen(width, MIN_HEIGHT, |frame| {
                view.draw(frame, &review, Duration::ZERO)
            });
            assert_eq!(confirmation.lines().nth(3).unwrap().trim_end(), expected);
        }
    }

    #[test]
    fn review_layout_highlights_command_target_and_active_page() {
        let review = fixture_review(|w| {
            w.intent.account = sigrund_core::host::Account::Numeric {
                uid: 0,
                gid: 0,
                supplementary_gids: vec![],
            };
            w.execution_context.target_uid = 0;
            w.execution_context.target_gid = 0;
        });
        let pages = ReviewPages::new(&review);
        let mut view = ReviewView::default();
        view.resize(&pages.pages[0], Rect::new(0, 0, 80, 24));
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();
        terminal
            .draw(|frame| view.draw(frame, &review, Duration::from_secs(90)))
            .unwrap();
        let buffer = terminal.backend().buffer();
        assert_eq!(buffer[(2, BODY_TOP)].fg, Color::Cyan);
        assert_eq!(buffer[(0, 2)].bg, Color::Cyan);
        assert!(buffer.content().iter().any(|cell| cell.fg == Color::Yellow));
        assert!(
            buffer
                .content()
                .iter()
                .any(|cell| cell.fg == Color::Magenta)
        );

        // Optional artifacts show the real renderer's cells, rather than a
        // separate mockup, when reviewing presentation changes locally.
        if let Ok(directory) = std::env::var("SIGRUND_TUI_PREVIEW_DIR") {
            let directory = std::path::Path::new(&directory);
            std::fs::create_dir_all(directory).unwrap();
            for (tab, name) in ["review", "arguments", "environment", "access", "evidence"]
                .into_iter()
                .enumerate()
            {
                view.tab = tab;
                view.rows.clear();
                view.resize(&pages.pages[tab], Rect::new(0, 0, 80, 24));
                terminal
                    .draw(|frame| view.draw(frame, &review, Duration::from_secs(90)))
                    .unwrap();
                let cells = terminal.backend().buffer().content().iter().map(|cell| serde_json::json!({"text":cell.symbol(),"fg":format!("{:?}",cell.fg),"bg":format!("{:?}",cell.bg),"bold":cell.modifier.contains(Modifier::BOLD)})).collect::<Vec<_>>();
                std::fs::write(
                    directory.join(format!("{name}.json")),
                    serde_json::to_vec(&serde_json::json!({"width":80,"height":24,"cells":cells}))
                        .unwrap(),
                )
                .unwrap();
            }
        }
    }

    #[test]
    fn reconnect_clears_connection_errors_and_preserves_request_results() {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let (_master, tty) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        assert_eq!(
            unsafe { libc::fcntl(tty.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let mut screen = Screen::new(&tty);
        for kind in [io::ErrorKind::UnexpectedEof, io::ErrorKind::TimedOut] {
            screen.reconnecting(&tty, &kind.into()).unwrap();
            let disconnected = screen.status;
            assert!(!disconnected.is_empty());
            assert!(!screen.idle(false).unwrap());
            assert_eq!(screen.status, disconnected);
            assert!(!screen.idle(true).unwrap());
            assert_eq!(screen.status, "");
        }
        for status in ["Submission unconfirmed", INVALID_WARRANT, "Decision sent"] {
            screen.status = status;
            assert!(!screen.idle(true).unwrap());
            assert_eq!(screen.status, status);
        }
    }

    #[test]
    fn unchanged_idle_view_does_not_write_to_the_terminal() {
        let (mut master, mut slave) = (-1, -1);
        let mut size = libc::winsize {
            ws_row: 12,
            ws_col: 80,
            ws_xpixel: 0,
            ws_ypixel: 0,
        };
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    &size,
                )
            },
            0
        );
        let (mut master, tty) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        for fd in [master.as_raw_fd(), tty.as_raw_fd()] {
            assert_eq!(
                unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) },
                0
            );
        }
        fn drain(master: &mut File) -> String {
            let mut bytes = Vec::new();
            assert_eq!(
                master.read_to_end(&mut bytes).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
            String::from_utf8(bytes).unwrap()
        }
        fn frame_output(master: &mut File) -> String {
            poll(
                &mut [event(master.as_raw_fd(), libc::POLLIN)],
                Some(Instant::now() + Duration::from_secs(1)),
            )
            .unwrap();
            drain(master)
        }

        let mut screen = Screen::new(&tty);
        assert!(!screen.idle(true).unwrap());
        assert!(frame_output(&mut master).contains("Waiting"));
        assert!(!screen.idle(true).unwrap());
        assert!(drain(&mut master).is_empty());

        screen.decision_sent();
        assert!(!screen.idle(true).unwrap());
        assert!(frame_output(&mut master).contains("Decision"));
        assert!(!screen.idle(false).unwrap());
        assert!(frame_output(&mut master).contains("Reconnecting"));

        size.ws_col = 90;
        assert_eq!(
            unsafe { libc::ioctl(tty.as_raw_fd(), libc::TIOCSWINSZ, &size) },
            0
        );
        assert!(!screen.idle(false).unwrap());
        assert!(!frame_output(&mut master).is_empty());

        let area = screen.size().unwrap();
        screen
            .paint(area, None, |frame| {
                line(frame, 0, "Review", Style::default())
            })
            .unwrap();
        frame_output(&mut master);
        assert!(!screen.idle(false).unwrap());
        assert!(frame_output(&mut master).contains("Reconnecting"));

        screen.renderer = None;
        assert!(!screen.idle(false).unwrap());
        assert!(frame_output(&mut master).contains("Reconnecting"));

        master.write_all(b"q").unwrap();
        poll(&mut [event(tty.as_raw_fd(), libc::POLLIN)], None).unwrap();
        assert!(screen.idle(false).unwrap());
        assert!(drain(&mut master).is_empty());
    }

    #[test]
    fn terminal_write_keeps_running_while_slow_output_drains() {
        let mut descriptors = [-1; 2];
        assert_eq!(
            unsafe { libc::pipe2(descriptors.as_mut_ptr(), libc::O_CLOEXEC) },
            0
        );
        let [mut reader, writer] = descriptors.map(|fd| unsafe { File::from_raw_fd(fd) });
        let capacity = unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETPIPE_SZ, 4096) };
        assert!(capacity >= 4096);
        let capacity = capacity as usize;
        assert_eq!(
            unsafe { libc::fcntl(writer.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let payload = vec![b'x'; capacity * 8];
        std::thread::scope(|scope| {
            let drain = scope.spawn(move || {
                let mut received = Vec::new();
                let mut chunk = vec![0; capacity];
                loop {
                    let count = reader.read(&mut chunk).unwrap();
                    if count == 0 {
                        return received;
                    }
                    received.extend_from_slice(&chunk[..count]);
                    std::thread::sleep(Duration::from_millis(60));
                }
            });
            let result = write_terminal(&writer, &payload, None);
            drop(writer);
            assert_eq!(drain.join().unwrap(), payload);
            result.unwrap();
        });
    }

    #[test]
    fn large_paste_can_cross_the_prompt_drain_batch_limit() {
        use std::{os::fd::OwnedFd, os::unix::net::UnixStream};

        let (reader, mut writer) = UnixStream::pair().unwrap();
        reader.set_nonblocking(true).unwrap();
        let tty = File::from(OwnedFd::from(reader));
        let mut screen = Screen::new(&tty);
        writer.write_all(b"\x1b[200~").unwrap();
        writer.write_all(&[b'x'; 6000]).unwrap();
        writer.write_all(b"yes\r").unwrap();
        screen.discard_keys(None).unwrap();
        assert!(screen.discarding_input);
        screen.discard_keys(None).unwrap();
        assert!(!screen.discarding_input);
        writer.write_all(b"yes\r\x1b[201~q").unwrap();
        assert!(screen.key().unwrap() == Some(Key::Char(b'q')));
    }

    #[test]
    fn prompt_discards_input_arriving_during_render_and_keeps_partial_paste() {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                    std::ptr::null(),
                )
            },
            0
        );
        let (mut master, tty) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        assert_eq!(
            unsafe { libc::fcntl(tty.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let mut screen = Screen::new(&tty);
        let area = Rect::new(0, 0, 48, 10);
        screen
            .paint(area, None, |frame| draw_idle(frame, true, "", false))
            .unwrap();
        screen
            .paint_prompt(area, None, |frame| {
                master.write_all(b"yes\r\x1b[200").unwrap();
                line(frame, 1, "Type yes + Enter", Style::default());
            })
            .unwrap();
        master.write_all(b"~yes\r\x1b[201~").unwrap();
        poll(&mut [event(tty.as_raw_fd(), libc::POLLIN)], None).unwrap();
        assert!(screen.key().unwrap() == Some(Key::Paste));
        assert!(screen.key().unwrap().is_none());
        master.write_all(b"yes\r").unwrap();
        poll(&mut [event(tty.as_raw_fd(), libc::POLLIN)], None).unwrap();
        for key in [
            Key::Char(b'y'),
            Key::Char(b'e'),
            Key::Char(b's'),
            Key::Enter,
        ] {
            assert!(screen.key().unwrap() == Some(key));
        }
    }

    fn screen(width: u16, height: u16, draw: impl FnOnce(&mut Frame<'_>)) -> String {
        let mut terminal = Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(draw).unwrap();
        terminal
            .backend()
            .buffer()
            .content()
            .chunks(usize::from(width))
            .map(|row| row.iter().map(|cell| cell.symbol()).collect::<String>())
            .collect::<Vec<_>>()
            .join("\n")
    }

    #[test]
    fn renders_connection_status_without_claiming_authorization() {
        let idle = screen(48, 10, |frame| {
            draw_idle(frame, true, "Decision sent", false)
        });
        assert!(idle.contains("Connected"));
        assert!(idle.contains("Waiting for a request"));
        assert!(idle.contains("Decision sent"));
        let lost = screen(48, 10, |frame| {
            draw_idle(frame, false, "Submission unconfirmed", false)
        });
        assert!(lost.contains("Reconnecting"));
        assert!(lost.contains("Submission unconfirmed"));
        assert!(!lost.contains("Waiting for a request"));
    }

    #[test]
    fn long_escaped_values_remain_reachable_after_resize() {
        let mut review = fixture_review(|_| {});
        review.full_host_root = true;
        let value = format!("{}\x1b\u{202e}last", "x".repeat(4_000));
        let text = format!("argv[1] = {}", quote(&value));
        let mut view = ReviewView::default();
        view.resize(&text, Rect::new(0, 0, 40, 9));
        assert!(matches!(view.handle(Key::Char(b'a')), Interaction::Prompt));
        view.resize(&text, Rect::new(0, 0, 40, 9));
        let confirmation = screen(40, 9, |frame| view.draw(frame, &review, Duration::ZERO));
        assert!(confirmation.contains("FULL HOST ROOT AUTHORITY"));
        assert!(confirmation.contains("Time left: 0s"));
        assert!(confirmation.contains("Type yes + Enter"));
        view.resize(&text, Rect::new(0, 0, 20, 6));
        assert!(matches!(view.handle(Key::Enter), Interaction::Continue));
        let narrow = screen(20, 6, |frame| view.draw(frame, &review, Duration::ZERO));
        assert!(narrow.contains("Enlarge terminal"));
        view.resize(&text, Rect::new(0, 0, 62, 10));
        view.handle(Key::End);
        let tail = screen(62, 10, |frame| view.draw(frame, &review, Duration::ZERO));
        let visible_tail = tail
            .lines()
            .filter_map(|line| line.strip_prefix("> "))
            .map(str::trim_end)
            .collect::<String>();
        assert!(visible_tail.ends_with(r#"\u{001B}\u{202E}last""#), "{tail}");
        assert!(!tail.contains(['\x1b', '\u{202e}']));
    }

    #[test]
    fn expired_escape_preserves_a_queued_shortcut() {
        let (mut master, mut slave) = (-1, -1);
        assert_eq!(
            unsafe {
                libc::openpty(
                    &mut master,
                    &mut slave,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            },
            0
        );
        let (mut master, tty) = unsafe { (File::from_raw_fd(master), File::from_raw_fd(slave)) };
        assert_eq!(
            unsafe { libc::fcntl(tty.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) },
            0
        );
        let mut screen = Screen::new(&tty);
        screen.paint_idle(true, None).unwrap();
        screen.input = Input::Escape(Some(Instant::now()));
        master.write_all(b"r").unwrap();
        poll(&mut [event(tty.as_raw_fd(), libc::POLLIN)], None).unwrap();

        let mut view = ReviewView::default();
        assert!(matches!(view.handle(Key::Char(b'a')), Interaction::Prompt));
        let escape = screen.key().unwrap().unwrap();
        assert!(escape == Key::Escape);
        assert!(matches!(view.handle(escape), Interaction::Continue));
        let shortcut = screen.key().unwrap().unwrap();
        assert!(shortcut == Key::Char(b'r'));
        assert!(matches!(view.handle(shortcut), Interaction::Prompt));
        assert!(matches!(view.prompt, Prompt::Reject));
    }

    #[test]
    fn delayed_paste_opener_remains_suppressed_after_escape() {
        let mut input = Input::default();
        assert!(input.feed(27).is_none());
        let Input::Escape(Some(deadline)) = &mut input else {
            panic!("expected pending Escape");
        };
        *deadline = Instant::now();
        assert!(input.expire_escape() == Some(Key::Escape));
        assert!(input.expire_escape().is_none());

        let keys = b"[200~qayes\r\x1b[201~"
            .iter()
            .filter_map(|&byte| input.feed(byte))
            .collect::<Vec<_>>();
        assert!(keys == [Key::Paste]);
        assert!(input.feed(b'q') == Some(Key::Char(b'q')));

        let mut input = Input::Escape(Some(Instant::now()));
        assert!(input.expire_escape() == Some(Key::Escape));
        assert!(input.feed(b'q') == Some(Key::Char(b'q')));
    }

    #[test]
    fn paste_after_incomplete_csi_cannot_confirm_rejection() {
        for prefix in [b"\x1b[".as_slice(), b"\x1b[1;"] {
            let mut input = Input::default();
            let mut view = ReviewView::default();
            assert!(matches!(view.handle(Key::Char(b'r')), Interaction::Prompt));
            for &byte in prefix.iter().chain(b"\x1b[200~yes\r\x1b[201~") {
                if let Some(key) = input.feed(byte) {
                    assert!(matches!(view.handle(key), Interaction::Continue));
                }
            }
            assert!(matches!(
                view.handle(input.feed(b'\r').unwrap()),
                Interaction::Decide(Decision::Reject)
            ));
        }
    }

    #[test]
    fn interrupt_is_recognized_during_unterminated_paste() {
        for interrupt in [3, 26, 28] {
            let mut input = Input::default();
            let opener = b"\x1b[200~q\r"
                .iter()
                .filter_map(|&byte| input.feed(byte))
                .collect::<Vec<_>>();
            assert!(opener == [Key::Paste]);
            assert!(input.feed(interrupt) == Some(Key::Interrupt));
            assert!(input.feed(b'q').is_none());
            assert!(input.feed(b'\r').is_none());
        }
    }

    #[test]
    fn invalid_approval_input_shows_how_to_reset() {
        let review = fixture_review(|_| {});
        let pages = ReviewPages::new(&review);
        let mut view = ReviewView::default();
        view.resize(&pages.pages[0], Rect::new(0, 0, 40, 9));
        for invalid in [Key::Char(b'x'), Key::Paste] {
            view.handle(Key::Char(b'a'));
            for &byte in b"yes" {
                view.handle(Key::Char(byte));
            }
            view.handle(invalid);
            view.handle(Key::Backspace);
            let rendered = screen(40, 9, |frame| view.draw(frame, &review, Duration::ZERO));
            assert!(rendered.contains("Approval input invalid"));
            assert!(rendered.contains("Enter resets. Esc cancels."));
            assert!(matches!(view.handle(Key::Enter), Interaction::Continue));
            for &byte in b"yes" {
                view.handle(Key::Char(byte));
            }
            assert!(matches!(
                view.handle(Key::Enter),
                Interaction::Decide(Decision::Approve)
            ));
            view.handle(Key::Escape);
        }
    }

    #[test]
    fn paste_and_previous_confirmation_cannot_sign() {
        let mut input = Input::default();
        let mut view = ReviewView::default();
        assert!(matches!(view.handle(Key::Char(b'a')), Interaction::Prompt));
        for byte in b"\x1b[200~yes\r\x1b[201~\r" {
            if let Some(key) = input.feed(*byte) {
                assert!(matches!(view.handle(key), Interaction::Continue));
            }
        }
        for byte in b"yes" {
            view.handle(input.feed(*byte).unwrap());
        }
        let mut next = ReviewView::default();
        next.handle(Key::Char(b'a'));
        assert!(matches!(next.handle(Key::Enter), Interaction::Continue));
        assert!(matches!(
            view.handle(Key::Enter),
            Interaction::Decide(Decision::Approve)
        ));
        next.handle(Key::Escape);
        next.handle(Key::Char(b'r'));
        assert!(matches!(
            next.handle(Key::Enter),
            Interaction::Decide(Decision::Reject)
        ));
    }
}
