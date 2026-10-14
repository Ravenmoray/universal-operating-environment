"""Documentation consistency: relative Markdown links and anchors must resolve.

Only repository-relative targets are checked; external URLs are never fetched.
"""
from pathlib import Path
import re
import subprocess
import unittest
from urllib.parse import unquote

ROOT = Path(__file__).resolve().parents[1]
LINK = re.compile(r'(?<!\\)\[(?:[^\]\\]|\\.)*\]\(\s*<?([^)\s>]+)>?(?:\s+"[^"]*")?\s*\)')
FENCE = re.compile(r'^\s*(```|~~~)')


def markdown_files():
    listed = subprocess.run(['git', 'ls-files', '*.md'], cwd=ROOT, capture_output=True,
                            text=True, check=False)
    if listed.returncode == 0 and listed.stdout.strip():
        return sorted(ROOT / line for line in listed.stdout.splitlines())
    return sorted(p for p in ROOT.rglob('*.md') if '.git' not in p.parts)


def prose_lines(text):
    """Yield lines outside fenced code blocks."""
    fenced = False
    for line in text.splitlines():
        if FENCE.match(line):
            fenced = not fenced
            continue
        if not fenced:
            yield line


def slug(heading):
    heading = re.sub(r'`|\*|_(?=\S)', '', heading.strip().lower())
    heading = re.sub(r'\[([^\]]*)\]\([^)]*\)', r'\1', heading)
    heading = re.sub(r'[^\w\- ]', '', heading)
    return heading.replace(' ', '-')


def anchors(path):
    seen, found = {}, set()
    for line in prose_lines(path.read_text(encoding='utf-8')):
        match = re.match(r'#{1,6}\s+(.*?)\s*#*\s*$', line)
        if match:
            base = slug(match.group(1))
            count = seen.get(base, 0)
            seen[base] = count + 1
            found.add(base if count == 0 else f'{base}-{count}')
    return found


class DocumentationTests(unittest.TestCase):
    def test_relative_links_and_anchors_resolve(self):
        problems = []
        for path in markdown_files():
            for line in prose_lines(path.read_text(encoding='utf-8')):
                for target in LINK.findall(line):
                    if re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', target):
                        continue  # http(s), mailto, etc.: never fetched
                    file_part, _, fragment = unquote(target).partition('#')
                    destination = path if not file_part else (path.parent / file_part).resolve()
                    shown = path.relative_to(ROOT)
                    try:
                        destination.relative_to(ROOT)
                    except ValueError:
                        problems.append(f'{shown}: {target} escapes the repository')
                        continue
                    if not destination.exists():
                        problems.append(f'{shown}: {target} does not exist')
                    elif fragment and destination.suffix == '.md' and fragment not in anchors(destination):
                        problems.append(f'{shown}: {target} has no matching heading')
        self.assertEqual(problems, [], '\n'.join(problems))

    def test_every_research_note_is_reachable_from_the_readme_or_index(self):
        """New notes under docs/research must be linked from somewhere in the docs."""
        linked = set()
        for path in markdown_files():
            for line in prose_lines(path.read_text(encoding='utf-8')):
                for target in LINK.findall(line):
                    file_part = unquote(target).partition('#')[0]
                    if file_part and not re.match(r'^[a-zA-Z][a-zA-Z0-9+.-]*:', file_part):
                        linked.add((path.parent / file_part).resolve())
        orphans = [str(p.relative_to(ROOT)) for p in markdown_files()
                   if p.parent == ROOT / 'docs' / 'research' and p.name != 'README.md'
                   and p.resolve() not in linked]
        self.assertEqual(orphans, [], 'research notes not linked from any document')


if __name__ == '__main__':
    unittest.main()
