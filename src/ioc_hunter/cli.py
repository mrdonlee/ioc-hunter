"""ioc-hunter CLI entrypoint."""

from __future__ import annotations

import typer
from rich.console import Console

from ioc_hunter import __version__

app = typer.Typer(
    name="ioc-hunter",
    help="Async threat intelligence correlation engine for SOC analysts.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)
console = Console()


def _version_callback(value: bool) -> None:
    if value:
        console.print(f"[bold cyan]ioc-hunter[/] v{__version__}")
        raise typer.Exit()


@app.callback()
def main(
    version: bool = typer.Option(
        None,
        "--version",
        "-V",
        callback=_version_callback,
        is_eager=True,
        help="Show version and exit.",
    ),
) -> None:
    """Root callback — global flags only."""


if __name__ == "__main__":
    app()
