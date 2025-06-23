# 🔌 MCP Integration Guide

## Overview

FastMCP ThreatIntel seamlessly integrates with AI assistants through the Model Context Protocol (MCP). This allows your AI assistant to directly access threat intelligence capabilities through natural language prompts.

## Supported Platforms

- **🖥️ VSCode with Roo-Cline Extension**
- **🤖 Claude Desktop App**
- **🔧 Any MCP-Compatible Client**

## Quick Setup

### Prerequisites

1. **Install FastMCP ThreatIntel**:
   ```bash
   pip install fastmcp-threatintel
   # OR clone and install from source
   git clone https://github.com/4R9UN/fastmcp-threatintel.git
   cd fastmcp-threatintel && uv sync
   ```

2. **Configure API Keys**:
   ```bash
   # Run the interactive setup
   threatintel setup
   ```

## VSCode with Roo-Cline

### Installation Steps

1. **Install Extension**: Install [Roo-Cline](https://marketplace.visualstudio.com/items?itemName=RooVeterinaryInc.roo-cline) from VS Code Marketplace

2. **Open MCP Settings**:
   - Press `Ctrl+Shift+P` (or `Cmd+Shift+P` on Mac)
   - Type "Roo: Open MCP Settings"
   - This opens your `mcp_settings.json` file

3. **Add Configuration**:

   **For UV Installation:**
   ```json
   {
     "mcpServers": {
       "threatintel": {
         "command": "uv",
         "args": ["run", "threatintel", "server", "--port", "8001"],
         "cwd": "/absolute/path/to/fastmcp-threatintel",
         "env": {
           "VIRUSTOTAL_API_KEY": "your_key_here",
           "OTX_API_KEY": "your_key_here"
         }
       }
     }
   }
   ```

   **For pip Installation:**
   ```json
   {
     "mcpServers": {
       "threatintel": {
         "command": "threatintel",
         "args": ["server", "--port", "8001"],
         "env": {
           "VIRUSTOTAL_API_KEY": "your_key_here",
           "OTX_API_KEY": "your_key_here"
         }
       }
     }
   }
   ```

   **For Poetry Installation:**
   ```json
   {
     "mcpServers": {
       "threatintel": {
         "command": "poetry",
         "args": ["run", "threatintel", "server", "--port", "8001"],
         "cwd": "/absolute/path/to/fastmcp-threatintel"
       }
     }
   }
   ```

### Configuration Notes

- **`cwd`**: Must be the absolute path to your project directory
- **`port`**: Use a unique port (8001) to avoid conflicts
- **`env`**: API keys can be set here or in `.env` file in the project directory

## Claude Desktop App

### Setup Process

1. **Locate Configuration File**:
   - **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
   - **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

2. **Add Server Configuration**:
   ```json
   {
     "mcpServers": {
       "threatintel": {
         "command": "threatintel",
         "args": ["server"],
         "env": {
           "VIRUSTOTAL_API_KEY": "your_key_here",
           "OTX_API_KEY": "your_key_here",
           "ABUSEIPDB_API_KEY": "your_key_here",
           "IPINFO_API_KEY": "your_key_here"
         }
       }
     }
   }
   ```

3. **Restart Claude Desktop**: Close and reopen the application

## Advanced Configuration

### Custom Port Configuration

```json
{
  "mcpServers": {
    "threatintel": {
      "command": "threatintel",
      "args": ["server", "--host", "0.0.0.0", "--port", "8002"],
      "env": {
        "LOG_LEVEL": "DEBUG"
      }
    }
  }
}
```

### Virtual Environment Setup

For Python virtual environments:

```json
{
  "mcpServers": {
    "threatintel": {
      "command": "/path/to/venv/bin/python",
      "args": ["-m", "threatintel.cli", "server", "--port", "8001"],
      "cwd": "/path/to/project"
    }
  }
}
```

## Testing Integration

### Verification Steps

1. **Check Server Status**:
   ```bash
   # Test if server starts correctly
   threatintel server --port 8001
   ```

2. **Test MCP Connection**:
   - Open your AI assistant
   - Look for "threatintel" in available tools
   - Try a simple command: `@threatintel analyze 8.8.8.8`

### Example Prompts

**Basic Analysis:**
```
@threatintel Can you analyze the IP address 192.168.1.1?
```

**Batch Analysis:**
```
@threatintel Analyze these IOCs: 8.8.8.8, google.com, d41d8cd98f00b204e9800998ecf8427e
```

**Advanced Analysis:**
```
@threatintel Perform a comprehensive threat analysis on 185.220.101.1 including APT attribution
```

## Troubleshooting

### Common Issues

1. **Server Not Starting**:
   ```bash
   # Check if all dependencies are installed
   threatintel --version
   
   # Verify API keys
   threatintel config
   ```

2. **Port Conflicts**:
   ```json
   // Use a different port
   "args": ["server", "--port", "8002"]
   ```

3. **Path Issues**:
   ```json
   // Ensure absolute paths
   "cwd": "/Users/username/projects/fastmcp-threatintel"
   ```

### Debug Mode

Enable debug logging:

```json
{
  "mcpServers": {
    "threatintel": {
      "command": "threatintel",
      "args": ["server", "--log-level", "DEBUG"],
      "env": {
        "DEBUG": "true"
      }
    }
  }
}
```

## Performance Optimization

### Resource Limits

```json
{
  "mcpServers": {
    "threatintel": {
      "command": "threatintel",
      "args": ["server"],
      "env": {
        "CACHE_TTL": "7200",
        "MAX_RETRIES": "3",
        "REQUEST_TIMEOUT": "30"
      }
    }
  }
}
```

### Memory Management

For large-scale analysis:

```json
{
  "env": {
    "PYTHON_OPTS": "-O",
    "MAX_WORKERS": "4",
    "BATCH_SIZE": "50"
  }
}
```

## Security Considerations

1. **API Key Protection**: Store keys securely, never commit to version control
2. **Network Security**: Use HTTPS for production deployments
3. **Access Control**: Limit server access to trusted clients only
4. **Log Security**: Avoid logging sensitive data

## Best Practices

1. **Use Environment Variables**: Store API keys in `.env` files
2. **Port Management**: Use unique ports for each MCP server
3. **Error Handling**: Configure proper error handling and retries
4. **Monitoring**: Enable logging for troubleshooting
5. **Updates**: Keep the package updated for latest features and security fixes

## Integration Examples

### Natural Language Queries

```
"Analyze this suspicious IP and tell me if it's associated with any known threats"
"Check if this domain has any malware associations"
"Generate a threat intelligence report for these IOCs"
"Perform APT attribution analysis on this infrastructure"
```

### Structured Queries

```json
{
  "tool": "analyze_iocs",
  "parameters": {
    "ioc_string": "8.8.8.8,google.com",
    "output_format": "html",
    "include_graph": true
  }
}