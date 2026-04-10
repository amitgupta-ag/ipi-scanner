"""IPI-Scanner CLI interface."""

import sys
import json
import click
from pathlib import Path

from ipi_scanner.scanner import Scanner
from ipi_scanner.output.cli_reporter import CliReporter
from ipi_scanner.output.json_reporter import JsonReporter
from ipi_scanner.output.html_reporter import HtmlReporter


@click.command()
@click.argument('path', type=click.Path(exists=True))
@click.option(
    '--mode',
    type=click.Choice(['strict', 'balanced', 'permissive']),
    default='balanced',
    help='Detection sensitivity mode'
)
@click.option(
    '--output',
    type=click.Choice(['cli', 'json', 'html']),
    default='cli',
    help='Output format'
)
@click.option(
    '--recursive/--no-recursive',
    default=True,
    help='Scan directories recursively'
)
@click.option(
    '--context',
    type=click.Choice(['untrusted', 'rag', 'agent', 'critical']),
    default=None,
    help='Scanning context for risk multipliers'
)
@click.option(
    '--output-file',
    type=click.Path(),
    default=None,
    help='Save output to file (for HTML)'
)
@click.option(
    '--summary',
    is_flag=True,
    help='Show summary only (batch mode)'
)
def main(path, mode, output, recursive, context, output_file, summary):
    """
    Detect Indirect Prompt Injection attacks in documents.
    
    Examples:
        ipi-scan document.pdf
        ipi-scan ./documents --recursive --mode strict
        ipi-scan document.pdf --output json
        ipi-scan ./docs --context rag --output html --output-file report.html
    """
    
    try:
        # Build context multipliers
        context_dict = {}
        if context:
            if context == 'untrusted':
                context_dict['untrusted_source'] = True
            elif context == 'rag':
                context_dict['rag_pipeline'] = True
                context_dict['untrusted_source'] = True
            elif context == 'agent':
                context_dict['agent_tool_access'] = True
                context_dict['untrusted_source'] = True
            elif context == 'critical':
                context_dict['agent_api_access'] = True
                context_dict['untrusted_source'] = True
        
        # Initialize scanner
        scanner = Scanner(mode=mode)
        
        # Scan
        path_obj = Path(path)
        if path_obj.is_dir():
            # Batch scan
            if recursive:
                files = list(path_obj.rglob('*'))
            else:
                files = list(path_obj.glob('*'))
            
            file_paths = [
                str(f) for f in files
                if f.is_file() and f.suffix.lower() in scanner.parser.SUPPORTED_EXTENSIONS
            ]
            
            if not file_paths:
                click.echo(f"No supported files found in {path}", err=True)
                sys.exit(1)
            
            result = scanner.batch_scan(file_paths, context_dict)
        else:
            # Single file scan
            result = scanner.scan_file(str(path), context_dict)
            # Wrap in batch format for consistency
            result = {
                'summary': {
                    'total_files': 1,
                    'scanned': 1 if result['status'] == 'success' else 0,
                    'errors': 1 if result['status'] == 'error' else 0,
                    'high_risk_count': 1 if result.get('risk_assessment', {}).get('score', 0) >= 50 else 0,
                    'total_detections': len(result.get('detections', []))
                },
                'high_risk_files': [(path, result.get('risk_assessment', {}).get('score', 0))]
                if result.get('risk_assessment', {}).get('score', 0) >= 50 else [],
                'detailed_results': [result]
            }
        
        # Format output
        if output == 'json':
            output_text = JsonReporter.report_batch(result)
        elif output == 'html':
            output_text = HtmlReporter.report_batch(result)
        else:  # cli
            if summary:
                output_text = CliReporter.report_summary(result)
            else:
                output_text = CliReporter.report_batch(result)
        
        # Write output
        if output_file:
            with open(output_file, 'w') as f:
                f.write(output_text)
            click.echo(f"✅ Report saved to {output_file}")
        else:
            click.echo(output_text)
        
        # Exit code based on results
        if result['summary']['high_risk_count'] > 0:
            sys.exit(1)
        else:
            sys.exit(0)
    
    except Exception as e:
        click.echo(f"❌ Error: {e}", err=True)
        sys.exit(1)


if __name__ == '__main__':
    main()
