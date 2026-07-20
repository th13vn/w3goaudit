import pathlib
import sys
import tempfile
import unittest


SCRIPTS = pathlib.Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS))

import check_markdown_links  # noqa: E402


class MarkdownLinkParserTest(unittest.TestCase):
    def test_balanced_and_escaped_parentheses(self):
        text = r"[balanced](guide_(v2).md) [escaped](escaped\).md)"
        self.assertEqual(
            list(check_markdown_links.inline_link_targets(text)),
            ["guide_(v2).md", r"escaped\).md"],
        )

    def test_target_extraction_handles_titles_and_angle_destinations(self):
        self.assertEqual(
            check_markdown_links.link_target('guide_(v2).md "Guide"'),
            "guide_(v2).md",
        )
        self.assertEqual(
            check_markdown_links.link_target("<docs/guide with spaces.md> 'Guide'"),
            "docs/guide with spaces.md",
        )

    def test_title_parentheses_do_not_hide_a_broken_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "README.md"
            source.write_text(
                '[missing](missing.md "unmatched title (")\n',
                encoding="utf-8",
            )
            self.assertEqual(
                check_markdown_links.broken_links(root, [source]),
                ["README.md -> missing.md"],
            )

    def test_absolute_uris_and_network_paths_are_not_local_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "README.md"
            source.write_text(
                "[ftp](ftp://example.com/file)\n"
                "[network](//example.com/file)\n"
                "[custom](urn:example:document)\n",
                encoding="utf-8",
            )
            self.assertEqual(check_markdown_links.broken_links(root, [source]), [])

    def test_broken_links_uses_complete_destination(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "README.md"
            (root / "guide_(v2).md").touch()
            (root / "escaped).md").touch()
            source.write_text(
                r"[balanced](guide_(v2).md) [escaped](escaped\).md)",
                encoding="utf-8",
            )
            self.assertEqual(check_markdown_links.broken_links(root, [source]), [])

            source.write_text("[missing](missing_(v2).md)", encoding="utf-8")
            self.assertEqual(
                check_markdown_links.broken_links(root, [source]),
                ["README.md -> missing_(v2).md"],
            )

    def test_commonmark_fenced_code_links_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "README.md"
            blocks = []
            for indent in range(4):
                blocks.extend(
                    [
                        f"{' ' * indent}```md\n",
                        f"[example](missing-{indent}.md)\n",
                        f"{' ' * (3 - indent)}`````\n",
                    ]
                )
            blocks.extend(
                [
                    "  ~~~\n",
                    "[other](also-missing.md)\n",
                    " ~~~~\n",
                ]
            )
            source.write_text("".join(blocks), encoding="utf-8")
            self.assertEqual(check_markdown_links.broken_links(root, [source]), [])

    def test_inline_code_span_links_are_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "README.md"
            source.write_text(
                "`[example](missing.md)`\n"
                "``code ` [other](also-missing.md)``\n",
                encoding="utf-8",
            )
            self.assertEqual(check_markdown_links.broken_links(root, [source]), [])

    def test_unclosed_fence_runs_to_end_of_document(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            source = root / "README.md"
            source.write_text(
                " ```md\n[example](missing.md)\n",
                encoding="utf-8",
            )
            self.assertEqual(check_markdown_links.broken_links(root, [source]), [])


if __name__ == "__main__":
    unittest.main()
