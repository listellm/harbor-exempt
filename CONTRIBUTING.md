# Contributing to Harbor Exempt

Thanks for your interest in contributing! This document outlines how to get involved.

Please note that this project is released with a [Code of Conduct](CODE_OF_CONDUCT.md). By participating, you are expected to uphold it.

## Getting Started

1. Fork the repository
2. Clone your fork locally
3. Create a feature branch from `main`
4. Make your changes
5. Test your changes (see [Testing](#testing))
6. Submit a pull request

## Development Setup

### Prerequisites

- Docker installed and running
- Python 3.13+ (for local development without Docker)
- PostgreSQL (or use the in-cluster StatefulSet via Helm for dev)
- Access to a Harbor instance (for integration testing)

### Building

```bash
docker build -t harbor-exempt:dev image/
```

### Running Locally

```bash
cd image
pip install -r requirements.txt
uvicorn app.main:app --reload --port 8000
```

Set all `HARBOR_EXEMPT_*` environment variables before running. See `image/app/config.py` for the full list.

### Testing

```bash
# Lint the Helm chart
helm lint helm/ -f helm/linter_values.yaml
```

## Guidelines

- **British English**: Use British English in code, comments, and documentation.
- **Minimal dependencies**: Avoid adding new dependencies unless absolutely necessary.
- **Error handling**: Catch exceptions and return user-friendly error messages; don't let unhandled exceptions propagate.
- **No partial implementations**: All contributions should be complete and functional.

## Pull Requests

- Keep PRs focused on a single change
- Include a clear description of what and why
- Update documentation if adding or changing functionality
- Ensure the Docker image builds cleanly

## Reporting Issues

- Use GitHub Issues for bug reports and feature requests
- For bugs, include steps to reproduce and any relevant logs

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
