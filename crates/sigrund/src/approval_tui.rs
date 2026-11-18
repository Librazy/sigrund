//! The renderer writes to the verified TTY. Terminal input never uses stdin.
use crate::approver::{
    Decision, Exchange, Frontend, Review, discard_confirmation_input, event, poll, quote,
};
use ratatui::{
    Frame, Terminal, TerminalOptions, Viewport,
    backend::CrosstermBackend,
    layout::Rect,
    style::{Color, Modifier, Style},
    widgets::Paragraph,
};
use std::{
    cell::RefCell,
    fmt::Write as _,
    fs::File,
    io::{self, Read, Write},
    os::fd::AsRawFd,
    time::{Duration, Instant},
};

const ENTER: &[u8] = b"\x1b[?1049h\x1b[?25l\x1b[?2004h";
const LEAVE: &[u8] = b"\x18\x1b[0m\x1b[?2004l\x1b[?1049l\x1b[?25h";
const REFRESH: Duration = Duration::from_millis(100);
const ESCAPE_WAIT: Duration = Duration::from_millis(40);
const MIN_WIDTH: u16 = 40;
const MIN_HEIGHT: u16 = 9;
const BODY_TOP: u16 = 3;
const FOOTER_ROWS: u16 = 3;

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
    renderer: Option<Renderer>,
    output: FrameOutput,
    input: Input,
    status: &'static str,
}

impl<'a> Screen<'a> {
    pub(crate) fn new(tty: &'a File) -> Self {
        Self {
            tty,
            original: None,
            renderer: None,
            output: FrameOutput::default(),
            input: Input::default(),
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

    fn enter(&mut self, area: Rect) -> io::Result<()> {
        let mut original = unsafe { std::mem::zeroed() };
        if unsafe { libc::tcgetattr(self.tty.as_raw_fd(), &mut original) } < 0 {
            return Err(io::Error::last_os_error());
        }
        let mut raw = original;
        unsafe { libc::cfmakeraw(&mut raw) };
        self.original = Some(original);
        set_attributes(self.tty, &raw)?;
        discard_confirmation_input(self.tty)?;
        self.input = Input::default();
        write_terminal(self.tty, ENTER)?;
        self.renderer = Some(Terminal::with_options(
            CrosstermBackend::new(self.output.clone()),
            TerminalOptions {
                viewport: Viewport::Fixed(area),
            },
        )?);
        self.renderer.as_mut().unwrap().clear()?;
        Ok(())
    }

    fn leave(&mut self) -> io::Result<()> {
        self.renderer = None;
        self.output.0.borrow_mut().clear();
        if let Some(original) = self.original {
            let input = discard_confirmation_input(self.tty);
            let attributes = set_attributes(self.tty, &original);
            let display = write_terminal(self.tty, LEAVE);
            if attributes.is_ok() && display.is_ok() {
                self.original = None;
            }
            attributes.and(display).and(input)?;
        }
        Ok(())
    }

    fn paint(&mut self, area: Rect, draw: impl FnOnce(&mut Frame<'_>)) -> io::Result<()> {
        if self.renderer.is_none() {
            self.enter(area)?;
        }
        let terminal = self.renderer.as_mut().expect("active renderer");
        if terminal.get_frame().area() != area {
            terminal.resize(area)?;
        }
        terminal.draw(draw)?;
        let mut output = self.output.0.borrow_mut();
        let result = write_terminal(self.tty, &output);
        output.clear();
        result
    }

    fn paint_prompt(&mut self, area: Rect, draw: impl FnOnce(&mut Frame<'_>)) -> io::Result<()> {
        self.paint(area, draw)?;
        self.discard_keys()
    }

    fn read_byte(&self) -> io::Result<Option<u8>> {
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
            let Some(byte) = self.read_byte()? else {
                return Ok(self.input.expire_escape());
            };
            if let Some(key) = self.input.feed(byte) {
                return Ok(Some(key));
            }
        }
        Ok(None)
    }

    fn discard_keys(&mut self) -> io::Result<()> {
        // A paste may straddle a request or dialog boundary. Read through the
        // decoder so a previously read paste opener still suppresses its tail.
        for _ in 0..4096 {
            let Some(byte) = self.read_byte()? else {
                self.input.expire_escape();
                return Ok(());
            };
            if self.input.feed(byte) == Some(Key::Interrupt) {
                return Err(io::ErrorKind::Interrupted.into());
            }
        }
        Err(io::Error::other("excess queued terminal input"))
    }
}

impl Drop for Screen<'_> {
    fn drop(&mut self) {
        let _ = self.leave();
    }
}

impl Frontend for Screen<'_> {
    fn tty_events(&self) -> i16 {
        libc::POLLIN
    }

    fn idle(&mut self, connected: bool) -> io::Result<bool> {
        let status = self.status;
        let area = self.size()?;
        self.paint(area, |frame| draw_idle(frame, connected, status))?;
        match self.key()? {
            Some(Key::Interrupt) => Err(io::ErrorKind::Interrupted.into()),
            Some(Key::Char(b'q')) => Ok(true),
            _ => Ok(false),
        }
    }

    fn review(
        &mut self,
        _tty: &File,
        review: &Review,
        exchange: &Exchange<'_>,
    ) -> io::Result<Decision> {
        let display = review_text(review);
        let mut view = ReviewView::default();
        let mut previous_size = None;
        loop {
            exchange.check()?;
            let area = self.size()?;
            view.resize(&display, area);
            let remaining = exchange.deadline.saturating_duration_since(Instant::now());
            self.paint(area, |frame| {
                view.draw(frame, review.target, review.full_host_root, remaining);
            })?;
            if previous_size.replace(area) != Some(area) {
                self.discard_keys()?;
            }
            match self.key()? {
                Some(Key::Interrupt) => return Err(io::ErrorKind::Interrupted.into()),
                Some(key) if fits(area) => match view.handle(key) {
                    Interaction::Continue => {}
                    Interaction::Prompt => {
                        self.paint_prompt(area, |frame| {
                            view.draw(frame, review.target, review.full_host_root, remaining);
                        })?;
                    }
                    Interaction::Decide(decision) if self.size()? == area => return Ok(decision),
                    Interaction::Decide(_) => view.prompt = Prompt::Review,
                },
                _ => {}
            }
            exchange.wait_input(self.tty, Instant::now() + REFRESH)?;
        }
    }

    fn before_signing(&mut self) -> io::Result<()> {
        self.leave()?;
        discard_confirmation_input(self.tty)?;
        write_terminal(self.tty, b"sigrund-approve-tui: signing with OpenSSH\n")
    }

    fn decision_sent(&mut self) {
        self.status = "Decision sent";
    }

    fn submission_interrupted(&mut self) {
        self.status = "Submission unconfirmed";
        if let Ok(area) = self.size() {
            let status = self.status;
            let _ = self.paint(area, |frame| draw_idle(frame, false, status));
        }
    }

    fn reconnecting(&mut self, _tty: &File, error: &io::Error) -> io::Result<()> {
        if self.status != "Submission unconfirmed" {
            self.status = if error.kind() == io::ErrorKind::TimedOut {
                "Approval timed out"
            } else {
                "Approval connection ended"
            };
        }
        if self.renderer.is_some() {
            self.discard_keys()?;
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

fn write_terminal(mut tty: &File, mut bytes: &[u8]) -> io::Result<()> {
    let deadline = Instant::now() + Duration::from_millis(250);
    while !bytes.is_empty() {
        if Instant::now() >= deadline {
            return Err(io::Error::other("operator terminal output stalled"));
        }
        match tty.write(bytes) {
            Ok(0) => return Err(io::ErrorKind::WriteZero.into()),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                poll(&mut [event(tty.as_raw_fd(), libc::POLLOUT)], Some(deadline))?;
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
    Interrupt,
    Other,
}

#[derive(Default)]
enum Input {
    #[default]
    Ground,
    Escape(Instant),
    Csi {
        bytes: [u8; 3],
        length: usize,
    },
    Paste(usize),
}

impl Input {
    fn expire_escape(&mut self) -> Option<Key> {
        if matches!(self, Self::Escape(deadline) if Instant::now() >= *deadline) {
            *self = Self::Ground;
            Some(Key::Escape)
        } else {
            None
        }
    }

    fn feed(&mut self, byte: u8) -> Option<Key> {
        match self {
            Self::Paste(matched) => {
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
            _ if matches!(byte, 3 | 26 | 28) => {
                *self = Self::Ground;
                Some(Key::Interrupt)
            }
            Self::Ground => match byte {
                27 => {
                    *self = Self::Escape(Instant::now() + ESCAPE_WAIT);
                    None
                }
                b'\r' | b'\n' => Some(Key::Enter),
                8 | 127 => Some(Key::Backspace),
                b' '..=b'~' => Some(Key::Char(byte)),
                _ => Some(Key::Other),
            },
            Self::Escape(_) => {
                *self = match byte {
                    b'[' | b'O' => Self::Csi {
                        bytes: [0; 3],
                        length: 0,
                    },
                    _ => Self::Ground,
                };
                matches!(self, Self::Ground).then_some(Key::Escape)
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
    rows: Vec<(bool, &'a str)>,
    prompt: Prompt,
}

impl<'a> ReviewView<'a> {
    fn resize(&mut self, display: &'a str, area: Rect) {
        if self.width != area.width {
            self.width = area.width;
            self.rows.clear();
            self.prompt = Prompt::Review;
        }
        if fits(area) && self.rows.is_empty() {
            self.rows = display
                .lines()
                .flat_map(|line| {
                    let width = usize::from(self.width.saturating_sub(2).max(1));
                    (0..line.len().max(1)).step_by(width).map(move |start| {
                        (start != 0, &line[start..(start + width).min(line.len())])
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
                (Prompt::Review, Key::Char(b'a' | b'r' | b'q')) => {
                    self.offset = 0;
                    self.prompt = match key {
                        Key::Char(b'a') => Prompt::Approve(String::new()),
                        Key::Char(b'r') => Prompt::Reject,
                        _ => Prompt::Quit,
                    };
                    return Interaction::Prompt;
                }
                (Prompt::Approve(answer), Key::Char(byte)) if answer.len() <= 3 => {
                    answer.push(char::from(byte));
                }
                (Prompt::Approve(answer), Key::Backspace) if answer.len() <= 3 => {
                    answer.pop();
                }
                (Prompt::Approve(answer), Key::Enter) if answer == "yes" => {
                    return Interaction::Decide(Decision::Approve);
                }
                (Prompt::Approve(answer), Key::Enter) => answer.clear(),
                (Prompt::Approve(answer), Key::Other | Key::Paste) => {
                    // Invalidate the line until Enter or Escape.
                    *answer = "    ".into();
                }
                (Prompt::Reject, Key::Enter) => return Interaction::Decide(Decision::Reject),
                (Prompt::Quit, Key::Enter) => return Interaction::Decide(Decision::Quit),
                _ => {}
            },
        }
        Interaction::Continue
    }

    fn draw(&self, frame: &mut Frame<'_>, target: &str, root: bool, remaining: Duration) {
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
            &format!("Time left: {}s", remaining.as_millis().div_ceil(1000)),
            Style::default(),
        );
        if root {
            line(
                frame,
                2,
                "FULL HOST ROOT AUTHORITY",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            );
        } else {
            line(
                frame,
                2,
                target,
                Style::default().add_modifier(Modifier::BOLD),
            );
        }
        for (index, (continued, text)) in self
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
                Style::default(),
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

fn draw_idle(frame: &mut Frame<'_>, connected: bool, status: &str) {
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
    if connected {
        line(frame, 2, "Waiting for a request", Style::default());
    }
    line(frame, 3, "q Quit", Style::default());
}

fn review_text(review: &Review) -> String {
    let warrant = review.csr.warrant();
    let command = &warrant.command;
    let context = &warrant.execution_context;
    let mut text = format!(
        "{}\nCommand {}\n{}: {}\nRequester UID {} / GID {}\nTarget UID {} / GID {}\nSigner {}\nProfile {}\nStdin {}\n",
        review.exec_id,
        quote(&command.executable_path),
        review.target,
        quote(&warrant.target_binding.description),
        warrant.requester_uid,
        warrant.requester_gid,
        context.target_uid,
        context.target_gid,
        quote(&review.signer_id),
        quote(&warrant.intent.security_profile),
        quote(&command.stdin_policy),
    );
    let _ = writeln!(
        text,
        "Capabilities: {}",
        if context.capabilities.is_empty() {
            "none".into()
        } else {
            context
                .capabilities
                .iter()
                .map(|name| quote(name))
                .collect::<Vec<_>>()
                .join(", ")
        }
    );
    for (index, arg) in command.argv.iter().enumerate() {
        let _ = writeln!(text, "argv[{index}] = {}", quote(arg));
    }
    text.push_str(&review.details);
    text
}

#[cfg(test)]
mod tests {
    use super::*;
    use ratatui::backend::TestBackend;
    use std::os::fd::FromRawFd;

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
            .paint(area, |frame| draw_idle(frame, true, ""))
            .unwrap();
        screen
            .paint_prompt(area, |frame| {
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
        let idle = screen(48, 10, |frame| draw_idle(frame, true, "Decision sent"));
        assert!(idle.contains("Connected"));
        assert!(idle.contains("Waiting for a request"));
        assert!(idle.contains("Decision sent"));
        let lost = screen(48, 10, |frame| {
            draw_idle(frame, false, "Submission unconfirmed")
        });
        assert!(lost.contains("Reconnecting"));
        assert!(lost.contains("Submission unconfirmed"));
        assert!(!lost.contains("Waiting for a request"));
    }

    #[test]
    fn long_escaped_values_remain_reachable_after_resize() {
        let value = format!("{}\x1b\u{202e}last", "x".repeat(4_000));
        let text = format!("argv[1] = {}", quote(&value));
        let mut view = ReviewView::default();
        view.resize(&text, Rect::new(0, 0, 40, 9));
        assert!(matches!(view.handle(Key::Char(b'a')), Interaction::Prompt));
        let confirmation = screen(40, 9, |frame| {
            view.draw(frame, "Host", true, Duration::ZERO)
        });
        assert!(confirmation.contains("FULL HOST ROOT AUTHORITY"));
        assert!(confirmation.contains("Time left: 0s"));
        assert!(confirmation.contains("Type yes + Enter"));
        view.resize(&text, Rect::new(0, 0, 20, 6));
        assert!(matches!(view.handle(Key::Enter), Interaction::Continue));
        let narrow = screen(20, 6, |frame| {
            view.draw(frame, "Host", true, Duration::ZERO)
        });
        assert!(narrow.contains("Enlarge terminal"));
        view.resize(&text, Rect::new(0, 0, 62, 10));
        view.handle(Key::End);
        let tail = screen(62, 10, |frame| {
            view.draw(frame, "Host", true, Duration::ZERO)
        });
        let visible_tail = tail
            .lines()
            .filter_map(|line| line.strip_prefix("> "))
            .map(str::trim_end)
            .collect::<String>();
        assert!(visible_tail.ends_with(r#"\u{001B}\u{202E}last""#), "{tail}");
        assert!(!tail.contains(['\x1b', '\u{202e}']));
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
