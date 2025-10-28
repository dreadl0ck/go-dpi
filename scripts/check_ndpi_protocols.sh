#!/bin/bash
# Script to check nDPI protocol mapping status
# Usage: ./scripts/check_ndpi_protocols.sh [path_to_ndpi_repo]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GODPI_ROOT="$(dirname "$SCRIPT_DIR")"
NDPI_WRAPPER="$GODPI_ROOT/modules/wrappers/nDPI_wrapper.go"

echo "===================================="
echo "nDPI Protocol Mapping Status Check"
echo "===================================="
echo ""

# Check current local mapping
echo "📊 Current Local Mapping:"
HIGHEST_ID=$(grep -E "^\s+[0-9]+:" "$NDPI_WRAPPER" | tail -1 | awk -F: '{print $1}' | tr -d ' \t')
PROTOCOL_COUNT=$(grep -E "^\s+[0-9]+:" "$NDPI_WRAPPER" | wc -l | tr -d ' ')
LAST_PROTOCOL=$(grep -E "^\s+${HIGHEST_ID}:" "$NDPI_WRAPPER" | awk -F'types.' '{print $2}' | awk -F',' '{print $1}')

echo "  - Highest Protocol ID: $HIGHEST_ID"
echo "  - Total Mapped Protocols: $PROTOCOL_COUNT"
echo "  - Last Protocol: $LAST_PROTOCOL"
echo ""

# Check for gaps in protocol IDs
echo "🔍 Checking for gaps in protocol IDs..."
GAPS=$(awk -F: '/^\s+[0-9]+:/ {print $1}' "$NDPI_WRAPPER" | tr -d ' \t' | sort -n | awk 'NR>1 && $1!=p+1 {print p+1"-"$1-1} {p=$1}')
if [ -z "$GAPS" ]; then
    echo "  ✓ No gaps found in protocol ID sequence"
else
    echo "  ⚠ Gaps found in protocol IDs:"
    echo "$GAPS" | while read gap; do
        echo "    - Missing IDs: $gap"
    done
fi
echo ""

# Check latest nDPI release
echo "🌐 Latest nDPI Release Information:"
if command -v curl >/dev/null 2>&1; then
    LATEST_RELEASE=$(curl -s https://api.github.com/repos/ntop/nDPI/releases/latest 2>/dev/null)
    if [ $? -eq 0 ]; then
        VERSION=$(echo "$LATEST_RELEASE" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/' || echo "unknown")
        RELEASE_DATE=$(echo "$LATEST_RELEASE" | grep '"published_at"' | sed -E 's/.*"([^"]+)".*/\1/' | cut -d'T' -f1 || echo "unknown")
        RELEASE_NOTES=$(echo "$LATEST_RELEASE" | grep '"body"' | head -1 || echo "")
        
        echo "  - Latest Version: $VERSION"
        echo "  - Release Date: $RELEASE_DATE"
        echo "  - URL: https://github.com/ntop/nDPI/releases/tag/$VERSION"
    else
        echo "  ⚠ Could not fetch release information (network error)"
    fi
else
    echo "  ⚠ curl not available, cannot check latest release"
fi
echo ""

# If nDPI path provided, analyze it
if [ ! -z "$1" ] && [ -d "$1" ]; then
    NDPI_PATH="$1"
    echo "📁 Analyzing nDPI Repository: $NDPI_PATH"
    
    PROTOCOL_IDS_FILE="$NDPI_PATH/src/include/ndpi_protocol_ids.h"
    
    if [ -f "$PROTOCOL_IDS_FILE" ]; then
        echo "  ✓ Found ndpi_protocol_ids.h"
        
        # Extract protocol count from nDPI
        NDPI_PROTOCOL_COUNT=$(grep "NDPI_PROTOCOL_" "$PROTOCOL_IDS_FILE" | grep -v "NDPI_PROTOCOL_CATEGORY" | grep -v "/\*" | grep -v "^//" | wc -l | tr -d ' ')
        NDPI_LAST_PROTOCOL=$(grep "NDPI_LAST_IMPLEMENTED_PROTOCOL\|NDPI_MAX_SUPPORTED_PROTOCOLS" "$PROTOCOL_IDS_FILE" | head -1 || echo "Not found")
        
        echo "  - nDPI Protocol Definitions: ~$NDPI_PROTOCOL_COUNT entries"
        echo ""
        
        # Compare
        echo "📊 Comparison:"
        DIFF=$((NDPI_PROTOCOL_COUNT - PROTOCOL_COUNT))
        if [ $DIFF -gt 0 ]; then
            echo "  ⚠ Your wrapper may be missing approximately $DIFF protocol(s)"
            echo ""
            echo "  🔧 Recommended Actions:"
            echo "     1. Review $PROTOCOL_IDS_FILE"
            echo "     2. Look for protocols with ID > $HIGHEST_ID"
            echo "     3. Add missing protocols to types/protocols.go"
            echo "     4. Update the mapping in $NDPI_WRAPPER"
        elif [ $DIFF -lt 0 ]; then
            echo "  ⚠ Your wrapper has more entries than nDPI source"
            echo "     (This might include commented entries)"
        else
            echo "  ✓ Protocol counts appear to match"
        fi
        echo ""
        
        # Try to find potentially missing protocols
        echo "🔎 Recently Added Protocols (last 20 in nDPI):"
        grep "NDPI_PROTOCOL_" "$PROTOCOL_IDS_FILE" | grep -v "NDPI_PROTOCOL_CATEGORY" | grep -v "/\*" | grep -v "^//" | tail -20 | while read line; do
            # Extract protocol name
            PROTO=$(echo "$line" | sed -E 's/.*NDPI_PROTOCOL_([A-Z0-9_]+).*/\1/')
            # Check if it exists in wrapper
            if grep -q "types\.${PROTO}" "$NDPI_WRAPPER" 2>/dev/null; then
                echo "  ✓ $PROTO"
            else
                # Try common variations
                PROTO_LOWER=$(echo "$PROTO" | tr '[:upper:]' '[:lower:]')
                if grep -qi "$PROTO_LOWER" "$NDPI_WRAPPER" 2>/dev/null; then
                    echo "  ✓ $PROTO (variant found)"
                else
                    echo "  ⚠ $PROTO (possibly missing)"
                fi
            fi
        done
    else
        echo "  ✗ Could not find ndpi_protocol_ids.h"
        echo "    Expected at: $PROTOCOL_IDS_FILE"
    fi
    echo ""
else
    echo "💡 Tip: Provide path to nDPI repository for detailed comparison:"
    echo "   ./scripts/check_ndpi_protocols.sh /path/to/nDPI"
    echo ""
fi

echo "===================================="
echo "📖 For update instructions, see:"
echo "   $GODPI_ROOT/UPDATE_NDPI_PROTOCOLS.md"
echo "===================================="

