import pytest

from prscreen.diff import ChangeKind, DiffLine, DiffParseError, parse_diff

MODIFY = """\
diff --git a/app.py b/app.py
index 1111111..2222222 100644
--- a/app.py
+++ b/app.py
@@ -10,4 +10,5 @@ def main():
     keep = 1
-    old = 2
+    new = 2
+    extra = 3
     tail = 4
"""


def test_modified_file_line_numbers():
    (change,) = parse_diff(MODIFY).files
    assert change.path == "app.py"
    assert change.kind is ChangeKind.MODIFIED
    assert change.added == [DiffLine(11, "    new = 2"), DiffLine(12, "    extra = 3")]
    assert change.removed == [DiffLine(11, "    old = 2")]


def test_added_and_deleted_files():
    text = """\
diff --git a/new.sh b/new.sh
new file mode 100755
index 0000000..3333333
--- /dev/null
+++ b/new.sh
@@ -0,0 +1,2 @@
+#!/bin/sh
+echo hi
diff --git a/gone.txt b/gone.txt
deleted file mode 100644
index 4444444..0000000
--- a/gone.txt
+++ /dev/null
@@ -1 +0,0 @@
-bye
"""
    new, gone = parse_diff(text).files
    assert (new.path, new.kind, new.new_mode) == ("new.sh", ChangeKind.ADDED, "100755")
    assert new.became_executable
    assert [line.number for line in new.added] == [1, 2]
    assert (gone.path, gone.kind) == ("gone.txt", ChangeKind.DELETED)
    assert gone.removed == [DiffLine(1, "bye")]


def test_pure_rename_without_hunks():
    text = """\
diff --git a/src/old name.py b/src/new name.py
similarity index 100%
rename from src/old name.py
rename to src/new name.py
"""
    (change,) = parse_diff(text).files
    assert (change.path, change.old_path, change.kind) == ("src/new name.py", "src/old name.py", "renamed")
    assert change.added == []


def test_mode_change_on_path_with_spaces():
    text = """\
diff --git a/my b/file.sh b/my b/file.sh
old mode 100644
new mode 100755
"""
    (change,) = parse_diff(text).files
    assert change.path == "my b/file.sh"
    assert change.became_executable


def test_quoted_utf8_path():
    text = """\
diff --git "a/caf\\303\\251 \\"x\\".py" "b/caf\\303\\251 \\"x\\".py"
--- "a/caf\\303\\251 \\"x\\".py"
+++ "b/caf\\303\\251 \\"x\\".py"
@@ -1 +1 @@
-a
+b
"""
    (change,) = parse_diff(text).files
    assert change.path == 'café "x".py'


def test_binary_files_are_marked_and_patch_payload_ignored():
    text = """\
diff --git a/logo.png b/logo.png
index 5555555..6666666 100644
Binary files a/logo.png and b/logo.png differ
diff --git a/blob.bin b/blob.bin
new file mode 100644
index 0000000..7777777
GIT binary patch
literal 12
TcmZQzKn5TH0RR91

literal 0
HcmV?d00001

"""
    logo, blob = parse_diff(text).files
    assert logo.binary and blob.binary
    assert blob.kind is ChangeKind.ADDED
    assert logo.added == blob.added == []


def test_hunk_counts_beat_lookalike_header_lines():
    # A removed "-- note" line and an added "++ x" line look like ---/+++ headers once the
    # diff prefix is added. They must stay content of app.sql.
    text = """\
diff --git a/app.sql b/app.sql
--- a/app.sql
+++ b/app.sql
@@ -1,2 +1,2 @@
--- note
+++ x
 select 1;
"""
    (change,) = parse_diff(text).files
    assert change.removed == [DiffLine(1, "-- note")]
    assert change.added == [DiffLine(1, "++ x")]


def test_crlf_and_unicode_line_separators():
    text = (
        "diff --git a/a.js b/a.js\r\n--- a/a.js\r\n+++ b/a.js\r\n@@ -0,0 +1,1 @@\r\n"
        "+let a = 1;\u2028alert(1)\r\n"
    )
    (change,) = parse_diff(text).files
    assert change.added == [DiffLine(1, "let a = 1;\u2028alert(1)")]


def test_no_newline_marker_and_empty_context_line():
    text = """\
diff --git a/a.txt b/a.txt
--- a/a.txt
+++ b/a.txt
@@ -1,3 +1,3 @@
 one

-three
\\ No newline at end of file
+THREE
\\ No newline at end of file
"""
    (change,) = parse_diff(text).files
    assert change.removed == [DiffLine(3, "three")]
    assert change.added == [DiffLine(3, "THREE")]


def test_omitted_hunk_counts_default_to_one():
    text = "--- a/x\n+++ b/x\n@@ -5 +5 @@\n-a\n+b\n"
    (change,) = parse_diff(text).files
    assert change.added == [DiffLine(5, "b")]


def test_plain_unified_diff_with_several_files():
    text = """\
--- a/one.txt\t2026-11-02 10:00:00
+++ b/one.txt\t2026-11-02 10:00:01
@@ -1 +1 @@
-x
+y
--- a/two.txt
+++ b/two.txt
@@ -1 +1,2 @@
 z
+w
"""
    one, two = parse_diff(text).files
    assert (one.path, two.path) == ("one.txt", "two.txt")
    assert two.added == [DiffLine(2, "w")]


def test_truncated_hunk_keeps_what_was_read():
    text = "--- a/x\n+++ b/x\n@@ -1,1 +1,5 @@\n+a\n+b\n"
    (change,) = parse_diff(text).files
    assert [line.text for line in change.added] == ["a", "b"]


def test_malformed_hunk_line_stops_hunk_and_parsing_continues():
    text = "--- a/x\n+++ b/x\n@@ -1,1 +1,3 @@\n+a\ngarbage\n--- a/y\n+++ b/y\n@@ -0,0 +1 @@\n+c\n"
    x, y = parse_diff(text).files
    assert [line.text for line in x.added] == ["a"]
    assert [line.text for line in y.added] == ["c"]


def test_hunk_without_file_header_is_an_error():
    with pytest.raises(DiffParseError):
        parse_diff("@@ -1 +1 @@\n-a\n+b\n")


def test_combined_diff_is_rejected():
    with pytest.raises(DiffParseError, match="combined"):
        parse_diff("diff --cc file.txt\n")


def test_empty_input():
    assert parse_diff("").files == []
