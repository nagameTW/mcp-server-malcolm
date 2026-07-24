# syntax=docker/dockerfile:1
FROM python:3.11-slim

# Install the package from source. The build context is the repo root.
WORKDIR /app
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN pip install --no-cache-dir .

# Run as a non-root user.
RUN useradd --create-home --uid 10001 app
USER app

# stdio MCP server: the entry point speaks MCP over stdin/stdout.
# Connection settings come from MALCOLM_* environment variables at runtime.
ENTRYPOINT ["mcp-server-malcolm"]
