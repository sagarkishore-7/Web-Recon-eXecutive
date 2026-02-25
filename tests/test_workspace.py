from pathlib import Path

from wrx.workspace import init_workspace, slugify_target


def test_init_workspace_creates_expected_layout(tmp_path: Path) -> None:
    target = "Example.COM"
    root = init_workspace(tmp_path, target)

    assert root == tmp_path / "workspaces" / slugify_target(target)
    assert (root / "wrx.yaml").exists()
    assert (root / "runs").exists()
    assert (root / "raw").exists()
    assert (root / "data").exists()


def test_slugify_target() -> None:
    assert slugify_target("https://Example.com/path") == "example.com_path"
