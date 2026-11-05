"""Select a pushed commit or its open PR's verified test merge commit."""

import json
import os
from pathlib import Path
import subprocess
import time


def api(endpoint, *arguments):
    result = subprocess.run(
        ['gh', 'api', '--method', 'GET', endpoint, *arguments],
        check=True, stdout=subprocess.PIPE, text=True,
    )
    return json.loads(result.stdout)


def resolve(repository, ref, sha, event):
    if event not in ('push', 'workflow_dispatch') or not ref.startswith('refs/heads/'):
        return sha, 'Testing the event commit.'

    branch = ref.removeprefix('refs/heads/')
    owner = repository.split('/')[0]
    pages = api(
        f'repos/{repository}/pulls',
        '--field', 'state=open', '--field', f'head={owner}:{branch}',
        '--field', 'per_page=100', '--paginate', '--slurp',
    )
    pulls = [
        pull for page in pages for pull in page
        if (pull['head'].get('repo') or {}).get('full_name') == repository
        and pull['head']['ref'] == branch and pull['head']['sha'] == sha
    ]
    if not pulls:
        return sha, 'No open PR matches this pushed commit; testing the event commit.'
    if len(pulls) != 1:
        raise RuntimeError('Multiple open PRs match this commit; cannot choose one merge target.')

    number = pulls[0]['number']
    for attempt in range(10):
        if attempt:
            time.sleep(3)
        pull = api(f'repos/{repository}/pulls/{number}')
        if pull['state'] != 'open' or pull['head']['sha'] != sha:
            return sha, f'PR #{number} closed or moved; testing the original event commit.'
        if pull['mergeable'] is False:
            return sha, f'PR #{number} has merge conflicts; testing the event commit.'
        merge_sha = pull.get('merge_commit_sha')
        if pull['mergeable'] is True and merge_sha:
            commit = api(f'repos/{repository}/git/commits/{merge_sha}')
            parents = [parent['sha'] for parent in commit['parents']]
            if parents == [pull['base']['sha'], sha]:
                return merge_sha, f'Testing PR #{number} merged with base `{pull["base"]["sha"]}`.'

    raise RuntimeError(f'PR #{number} has no verified merge commit yet; rerun when GitHub finishes updating it.')


def main():
    sha, reason = resolve(
        os.environ['GITHUB_REPOSITORY'], os.environ['GITHUB_REF'],
        os.environ['GITHUB_SHA'], os.environ['GITHUB_EVENT_NAME'],
    )
    print(f'{reason}\nSelected revision: {sha}')
    with Path(os.environ['GITHUB_OUTPUT']).open('a') as output:
        output.write(f'sha={sha}\n')
    with Path(os.environ['GITHUB_STEP_SUMMARY']).open('a') as summary:
        summary.write(f'### Tested revision\n\n{reason}\n\nCheckout: `{sha}`\n\n')
        summary.write(f'Checks remain attached to event commit `{os.environ["GITHUB_SHA"]}`.\n')


if __name__ == '__main__':
    main()
