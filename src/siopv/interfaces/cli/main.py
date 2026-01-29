"""SIOPV CLI - Command Line Interface.

Main entry point for the vulnerability orchestration system.
"""

from pathlib import Path
from typing import Annotated

import typer

from siopv.infrastructure.config.settings import get_settings
from siopv.infrastructure.logging.setup import configure_logging, get_logger

app = typer.Typer(
    name="siopv",
    help="Sistema Inteligente de Orquestación y Priorización de Vulnerabilidades",
    no_args_is_help=True,
)


@app.callback()
def main(
    verbose: Annotated[
        bool,
        typer.Option("--verbose", "-v", help="Enable verbose output"),
    ] = False,
) -> None:
    """SIOPV - Intelligent Vulnerability Prioritization System."""
    settings = get_settings()
    configure_logging(
        level="DEBUG" if verbose else settings.log_level,
        json_format=settings.environment == "production",
    )


@app.command()
def process_report(
    report_path: Annotated[
        Path,
        typer.Argument(
            help="Path to Trivy JSON report",
            exists=True,
            readable=True,
        ),
    ],
    output_dir: Annotated[
        Path,
        typer.Option("--output", "-o", help="Output directory for results"),
    ] = Path("./output"),
    batch_size: Annotated[
        int,
        typer.Option("--batch-size", "-b", help="Batch size for processing"),
    ] = 50,
) -> None:
    """Process a Trivy vulnerability report through the SIOPV pipeline."""
    log = get_logger(__name__)
    log.info("Processing report", report_path=str(report_path), batch_size=batch_size)

    # TODO: Implement ingestion pipeline
    typer.echo(f"Processing report: {report_path}")
    typer.echo(f"Output directory: {output_dir}")
    typer.echo("Pipeline execution not yet implemented.")


@app.command()
def dashboard() -> None:
    """Launch the Streamlit dashboard for Human-in-the-Loop review."""
    log = get_logger(__name__)
    log.info("Launching dashboard")

    # TODO: Implement Streamlit launcher
    typer.echo("Dashboard not yet implemented.")
    typer.echo("Will launch Streamlit at http://localhost:8501")


@app.command()
def train_model(
    dataset_path: Annotated[
        Path,
        typer.Argument(
            help="Path to training dataset (CSV)",
            exists=True,
            readable=True,
        ),
    ],
    output_path: Annotated[
        Path,
        typer.Option("--output", "-o", help="Path to save trained model"),
    ] = Path("./models/xgboost_risk_model.json"),
) -> None:
    """Train the XGBoost risk classification model."""
    log = get_logger(__name__)
    log.info("Training model", dataset_path=str(dataset_path))

    # TODO: Implement model training
    typer.echo(f"Training model with dataset: {dataset_path}")
    typer.echo(f"Model will be saved to: {output_path}")
    typer.echo("Model training not yet implemented.")


@app.command()
def version() -> None:
    """Show SIOPV version information."""
    typer.echo("SIOPV v0.1.0")
    typer.echo("Sistema Inteligente de Orquestación y Priorización de Vulnerabilidades")


if __name__ == "__main__":
    app()
