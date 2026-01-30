#!/bin/bash

# ============================================================================
# NMAP SCANNER TOOL - Enhanced Edition
# ============================================================================

# Color definitions
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
MAGENTA='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
GRAY='\033[0;90m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Configuration
OUTPUT_DIR="$HOME/nmap_scans"
TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
VERBOSE=false

# ============================================================================
# FUNCTIONS
# ============================================================================

print_banner() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "╔═══════════════════════════════════════════════════════════════╗"
    echo "║                                                               ║"
    echo "║              🔍 NMAP SCANNER TOOL - ENHANCED 🔍               ║"
    echo "║                                                               ║"
    echo "║              Network Reconnaissance Made Easy                 ║"
    echo "║                                                               ║"
    echo "╚═══════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

print_section() {
    echo -e "\n${BLUE}${BOLD}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${WHITE}$1${NC}"
    echo -e "${BLUE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n"
}

print_success() {
    echo -e "${GREEN}✓${NC} $1"
}

print_error() {
    echo -e "${RED}✗${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}⚠${NC} $1"
}

print_info() {
    echo -e "${CYAN}ℹ${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_warning "Some scans require root privileges for best results."
        echo -e "  ${GRAY}Run with 'sudo' for: SYN scan, OS detection, etc.${NC}"
        read -p "Continue anyway? (y/n): " continue_choice
        if [[ "$continue_choice" != "y" ]]; then
            exit 0
        fi
    else
        print_success "Running with root privileges"
    fi
}

check_nmap() {
    if ! command -v nmap &> /dev/null; then
        print_error "nmap is not installed!"
        echo -e "  ${GRAY}Install it with: sudo apt install nmap${NC}"
        exit 1
    fi
    print_success "nmap found: $(nmap --version | head -1)"
}

validate_ip() {
    local ip=$1
    
    # Check for CIDR notation
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$ ]]; then
        return 0
    fi
    
    # Check for IP range
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+-[0-9]+$ ]]; then
        return 0
    fi
    
    # Check for single IP
    if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    fi
    
    # Check for hostname
    if [[ $ip =~ ^[a-zA-Z0-9.-]+$ ]]; then
        return 0
    fi
    
    return 1
}

get_target() {
    print_section "🎯 TARGET SELECTION"
    
    echo -e "${WHITE}Enter target IP, range, or hostname:${NC}"
    echo -e "  ${GRAY}Examples:${NC}"
    echo -e "    ${CYAN}192.168.1.1${NC}           - Single IP"
    echo -e "    ${CYAN}192.168.1.0/24${NC}        - CIDR notation"
    echo -e "    ${CYAN}192.168.1.1-50${NC}        - Range"
    echo -e "    ${CYAN}scanme.nmap.org${NC}       - Hostname"
    echo
    
    while true; do
        read -p "$(echo -e ${GREEN}Target${NC}): " IP_IN
        
        if [[ -z "$IP_IN" ]]; then
            print_error "Target cannot be empty"
            continue
        fi
        
        if validate_ip "$IP_IN"; then
            print_success "Target validated: ${BOLD}$IP_IN${NC}"
            break
        else
            print_error "Invalid target format"
        fi
    done
}

setup_output() {
    mkdir -p "$OUTPUT_DIR"
    OUTPUT_FILE="$OUTPUT_DIR/scan_${TIMESTAMP}_$(echo $IP_IN | tr '/' '_' | tr '.' '_').txt"
    print_info "Results will be saved to: ${CYAN}$OUTPUT_FILE${NC}"
}

show_menu() {
    print_section "📋 SCAN TYPE SELECTION"
    
    echo -e "${BOLD}STEALTH & RECON SCANS${NC}"
    echo -e "  ${GREEN}[1]${NC}  TCP SYN Scan           ${GRAY}(Fast, stealthy half-open scan)${NC}"
    echo -e "  ${GREEN}[2]${NC}  TCP Connect Scan       ${GRAY}(Full connection, no root needed)${NC}"
    echo -e "  ${GREEN}[5]${NC}  Ping Sweep             ${GRAY}(Discover live hosts)${NC}"
    echo
    echo -e "${BOLD}ADVANCED SCANS${NC}"
    echo -e "  ${YELLOW}[3]${NC}  UDP Scan               ${GRAY}(Scan UDP ports - slow)${NC}"
    echo -e "  ${YELLOW}[4]${NC}  TCP ACK Scan           ${GRAY}(Firewall rule detection)${NC}"
    echo -e "  ${YELLOW}[10]${NC} OS & Service Detection ${GRAY}(Fingerprint OS and services)${NC}"
    echo
    echo -e "${BOLD}EVASION SCANS${NC}"
    echo -e "  ${MAGENTA}[6]${NC}  XMAS Scan              ${GRAY}(FIN, PSH, URG flags set)${NC}"
    echo -e "  ${MAGENTA}[8]${NC}  NULL Scan              ${GRAY}(No flags set)${NC}"
    echo -e "  ${MAGENTA}[9]${NC}  FIN Scan               ${GRAY}(FIN flag only)${NC}"
    echo
    echo -e "${BOLD}COMPREHENSIVE SCANS${NC}"
    echo -e "  ${CYAN}[12]${NC} Quick Scan             ${GRAY}(Top 100 ports)${NC}"
    echo -e "  ${CYAN}[13]${NC} Intense Scan           ${GRAY}(Aggressive, all ports)${NC}"
    echo -e "  ${CYAN}[14]${NC} Vulnerability Scan     ${GRAY}(NSE vuln scripts)${NC}"
    echo
    echo -e "${BOLD}OTHER OPTIONS${NC}"
    echo -e "  ${WHITE}[7]${NC}  Skip Ping (-Pn)        ${GRAY}(Scan even if host seems down)${NC}"
    echo -e "  ${WHITE}[15]${NC} Custom Command         ${GRAY}(Enter your own nmap flags)${NC}"
    echo -e "  ${RED}[0]${NC}  Exit                   ${GRAY}(Quit the tool)${NC}"
    echo
}

run_scan() {
    local scan_type=$1
    local nmap_cmd=""
    local description=""
    
    case $scan_type in
        1)
            description="TCP SYN Scan"
            nmap_cmd="nmap -sS -T4 -v"
            ;;
        2)
            description="TCP Connect Scan"
            nmap_cmd="nmap -sT -T4 -v"
            ;;
        3)
            description="UDP Scan"
            nmap_cmd="nmap -sU -T4 -v --top-ports 100"
            print_warning "UDP scans can be slow. Scanning top 100 ports only."
            ;;
        4)
            description="TCP ACK Scan"
            nmap_cmd="nmap -sA -T4 -v"
            ;;
        5)
            description="Ping Sweep"
            nmap_cmd="nmap -sn"
            ;;
        6)
            description="XMAS Scan"
            nmap_cmd="nmap -sX -T4 -v"
            ;;
        7)
            description="No Ping Scan"
            nmap_cmd="nmap -Pn -T4 -v"
            ;;
        8)
            description="NULL Scan"
            nmap_cmd="nmap -sN -T4 -v"
            ;;
        9)
            description="FIN Scan"
            nmap_cmd="nmap -sF -T4 -v"
            ;;
        10)
            description="OS & Service Detection"
            nmap_cmd="nmap -sV -O -A -T4 -v"
            print_warning "This scan is aggressive and may take time."
            ;;
        12)
            description="Quick Scan (Top 100)"
            nmap_cmd="nmap -T4 -F -v"
            ;;
        13)
            description="Intense Scan (All Ports)"
            nmap_cmd="nmap -p- -T4 -A -v"
            print_warning "Scanning all 65535 ports. This will take a while!"
            ;;
        14)
            description="Vulnerability Scan"
            nmap_cmd="nmap -sV --script vuln -T4 -v"
            print_warning "Running NSE vulnerability scripts..."
            ;;
        15)
            description="Custom Scan"
            echo -e "\n${YELLOW}Enter custom nmap flags:${NC}"
            read -p "$(echo -e ${CYAN}Flags${NC}): " custom_flags
            nmap_cmd="nmap $custom_flags"
            ;;
        *)
            print_error "Invalid option"
            return 1
            ;;
    esac
    
    print_section "🚀 EXECUTING: $description"
    
    echo -e "${GRAY}Command: $nmap_cmd \"$IP_IN\"${NC}\n"
    
    # Add progress indicator
    echo -e "${CYAN}Scan in progress...${NC}\n"
    
    # Execute scan and save output
    {
        echo "============================================"
        echo "Scan Type: $description"
        echo "Target: $IP_IN"
        echo "Date: $(date)"
        echo "Command: $nmap_cmd \"$IP_IN\""
        echo "============================================"
        echo
        eval "$nmap_cmd \"$IP_IN\""
        echo
    } | tee -a "$OUTPUT_FILE"
    
    echo
    print_success "Scan complete!"
    print_info "Results appended to: ${CYAN}$OUTPUT_FILE${NC}"
}

main_loop() {
    while true; do
        echo
        show_menu
        
        read -p "$(echo -e ${GREEN}Choose${NC} [0-15]): " NM_SEL
        
        case $NM_SEL in
            0)
                echo
                print_section "👋 GOODBYE"
                echo -e "${WHITE}Scan results saved in: ${CYAN}$OUTPUT_DIR${NC}"
                echo -e "${GRAY}Stay safe and scan responsibly!${NC}\n"
                exit 0
                ;;
            1|2|3|4|5|6|7|8|9|10|12|13|14|15)
                run_scan "$NM_SEL"
                ;;
            *)
                print_error "Invalid option. Choose 0-15."
                continue
                ;;
        esac
        
        # Ask if user wants to continue
        echo
        read -p "$(echo -e ${YELLOW}Run another scan?${NC} [y/n]): " CONTINUE
        if [[ "$CONTINUE" != "y" && "$CONTINUE" != "Y" ]]; then
            echo
            print_section "👋 GOODBYE"
            echo -e "${WHITE}Scan results saved in: ${CYAN}$OUTPUT_DIR${NC}"
            echo -e "${GRAY}Stay safe and scan responsibly!${NC}\n"
            exit 0
        fi
        
        clear
        print_banner
        echo -e "${GREEN}Current Target: ${BOLD}$IP_IN${NC}"
    done
}

# ============================================================================
# MAIN EXECUTION
# ============================================================================

print_banner

print_section "🔧 SYSTEM CHECK"
check_nmap
check_root

get_target
setup_output

clear
print_banner
echo -e "${GREEN}Target: ${BOLD}$IP_IN${NC}"

main_loop
