"""
Enhanced Windows BAM (Background Activity Moderator) Registry Parser
Supports multiple Windows versions with improved error handling and logging.
Created By 0xSCfL
"""

import windows
import json
import time
import struct
import logging
from datetime import datetime
from typing import List, Dict, Optional, Any
from pathlib import Path


class BamEntry:
    """Represents a BAM registry entry with executable information."""
    
    def __init__(self, pyhkey_sid):
        self.sid: str = pyhkey_sid.name
        self.executables: List[Dict[str, Any]] = []
        self._process_executables(pyhkey_sid)
    
    def _process_executables(self, pyhkey_sid) -> None:
        """Process all executable entries for this SID."""
        if not pyhkey_sid.values:
            logging.info(f"No values found for SID: {self.sid}")
            return
            
        for executable in pyhkey_sid.values:
            try:
                # Type 3 indicates REG_BINARY data containing timestamp
                if executable[2] == 3 and len(executable[1]) >= 8:
                    self._add_executable(executable)
                else:
                    logging.debug(f"Skipping non-timestamp value: {executable[0]}")
            except Exception as e:
                logging.error(f"Error processing executable {executable[0]}: {e}")
    
    def _add_executable(self, executable) -> None:
        """Add an executable entry with timestamp parsing."""
        try:
            path = executable[0]
            raw_data = executable[1]
            
            # Extract timestamp (first 8 bytes)
            timestamp = struct.unpack("<Q", raw_data[:8])[0]
            
            # Convert timestamp to readable format
            date = self._convert_timestamp(timestamp)
            
            # Extract additional data if available
            additional_data = None
            if len(raw_data) > 8:
                additional_data = raw_data[8:].hex()
            
            executable_info = {
                'path': path,
                'timestamp': date,
                'raw_timestamp': timestamp,
                'data_size': len(raw_data),
                'additional_data': additional_data
            }
            
            self.executables.append(executable_info)
            logging.debug(f"Added executable: {path} at {date}")
            
        except Exception as e:
            logging.error(f"Failed to add executable {executable[0]}: {e}")
    
    def _convert_timestamp(self, timestamp: int) -> str:
        """Convert Windows FILETIME to readable datetime string."""
        try:
            # Convert from Windows FILETIME (100-nanosecond intervals since 1601-01-01)
            # to Unix timestamp
            unix_timestamp = (timestamp / 10000000.0) - 11644473600
            
            if unix_timestamp < 0:
                return "Invalid timestamp"
                
            dt = datetime.fromtimestamp(unix_timestamp)
            return dt.strftime('%Y-%m-%d %H:%M:%S')
            
        except (ValueError, OSError) as e:
            logging.error(f"Failed to convert timestamp {timestamp}: {e}")
            return f"Invalid timestamp: {timestamp}"
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert BamEntry to dictionary for JSON serialization."""
        return {
            'sid': self.sid,
            'executable_count': len(self.executables),
            'executables': self.executables
        }


class BamParser:
    """Main BAM registry parser with support for multiple Windows versions."""
    
    # Supported Windows builds and their registry paths
    SUPPORTED_BUILDS = {
        # Windows 10 versions
        '16299': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings',  # 1709
        '17134': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings',  # 1803
        '17763': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 1809
        '18362': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 1903
        '18363': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 1909
        '19041': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 2004
        '19042': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 20H2
        '19043': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 21H1
        '19044': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 21H2
        '19045': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 22H2
        # Windows 11 versions
        '22000': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 21H2
        '22621': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 22H2
        '22631': r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings',  # 23H2
    }
    
    def __init__(self, log_level: int = logging.INFO):
        """Initialize the BAM parser with logging configuration."""
        self._setup_logging(log_level)
        self.registry = windows.system.registry
        self.build_number = str(windows.system.build_number)
        logging.info(f"Initialized BAM parser for Windows build: {self.build_number}")
    
    def _setup_logging(self, log_level: int) -> None:
        """Configure logging for the parser."""
        logging.basicConfig(
            level=log_level,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(),
                logging.FileHandler(f'bam_parser_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')
            ]
        )
    
    def get_registry_path(self) -> Optional[str]:
        """Get the appropriate registry path for the current Windows build."""
        # Check exact build match first
        if self.build_number in self.SUPPORTED_BUILDS:
            return self.SUPPORTED_BUILDS[self.build_number]
        
        # Check for partial matches (for newer builds)
        build_num = int(self.build_number)
        
        if build_num >= 22000:  # Windows 11
            return r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
        elif build_num >= 17763:  # Windows 10 1809+
            return r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings'
        elif build_num >= 16299:  # Windows 10 1709-1803
            return r'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\bam\UserSettings'
        
        return None
    
    def parse(self) -> List[Dict[str, Any]]:
        """Parse BAM registry entries and return structured data."""
        registry_path = self.get_registry_path()
        
        if not registry_path:
            raise ValueError(f"Unsupported Windows build: {self.build_number}")
        
        logging.info(f"Using registry path: {registry_path}")
        
        try:
            bamreg = self.registry(registry_path)
        except Exception as e:
            logging.error(f"Failed to access registry path {registry_path}: {e}")
            raise
        
        sids = bamreg.subkeys
        logging.info(f"Found {len(sids)} SID subkeys")
        
        bam_entries = []
        for sid_key in sids:
            try:
                logging.debug(f"Processing SID: {sid_key.name}")
                bam_entry = BamEntry(sid_key)
                if bam_entry.executables:  # Only add entries with executables
                    bam_entries.append(bam_entry.to_dict())
                    logging.info(f"Added {len(bam_entry.executables)} executables for SID: {sid_key.name}")
                else:
                    logging.debug(f"No executables found for SID: {sid_key.name}")
            except Exception as e:
                logging.error(f"Failed to process SID {sid_key.name}: {e}")
                continue
        
        logging.info(f"Successfully parsed {len(bam_entries)} BAM entries")
        return bam_entries
    
    def export_to_json(self, output_file: str = None) -> str:
        """Export BAM data to JSON file."""
        if not output_file:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            output_file = f"bam_export_{timestamp}.json"
        
        bam_data = self.parse()
        
        export_data = {
            'metadata': {
                'export_timestamp': datetime.now().isoformat(),
                'windows_build': self.build_number,
                'total_entries': len(bam_data),
                'total_executables': sum(entry['executable_count'] for entry in bam_data)
            },
            'bam_entries': bam_data
        }
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False)
            
            logging.info(f"Successfully exported BAM data to: {output_file}")
            return output_file
            
        except Exception as e:
            logging.error(f"Failed to export to {output_file}: {e}")
            raise
    
    def print_summary(self, top_count: int = 10) -> None:
        """Print a summary of BAM entries.
        
        Args:
            top_count: Number of most recent executables to display (default: 10)
        """
        try:
            bam_data = self.parse()
            
            print(f"\n{'='*60}")
            print(f"BAM Registry Analysis Summary")
            print(f"{'='*60}")
            print(f"Windows Build: {self.build_number}")
            print(f"Total SIDs processed: {len(bam_data)}")
            
            total_executables = sum(entry['executable_count'] for entry in bam_data)
            print(f"Total executables found: {total_executables}")
            
            if bam_data:
                print(f"\nTop {top_count} Most Recent Executables:")
                print(f"{'-'*60}")
                
                # Collect all executables with their SIDs
                all_executables = []
                for entry in bam_data:
                    for exe in entry['executables']:
                        exe['sid'] = entry['sid']
                        all_executables.append(exe)
                
                # Sort by timestamp (most recent first)
                all_executables.sort(key=lambda x: x['raw_timestamp'], reverse=True)
                
                # Show requested number of entries (or all if less available)
                display_count = min(top_count, len(all_executables))
                
                for i, exe in enumerate(all_executables[:display_count], 1):
                    print(f"{i:2d}. {exe['timestamp']} - {Path(exe['path']).name}")
                    print(f"    Full path: {exe['path']}")
                    print(f"    SID: {exe['sid']}")
                    print()
                
                if len(all_executables) > display_count:
                    remaining = len(all_executables) - display_count
                    print(f"... and {remaining} more executables")
            
        except Exception as e:
            logging.error(f"Failed to print summary: {e}")
            raise


def get_user_choice() -> int:
    """Get user's choice for number of recent programs to display.
    
    Returns:
        int: Number of programs to display, or -1 if user wants to exit
    """
    while True:
        try:
            print("\nChoose how many recent programs to display:")
            print("1. Top 10 (default)")
            print("2. Top 20")
            print("3. Top 30")
            print("4. Top 50")
            print("5. Top 100")
            print("6. All programs")
            print("7. Custom number")
            print("8. Exit")
            
            choice = input("\n► Enter your choice (1-8) or press Enter for default: ").strip()
            
            # Default choice (Enter pressed)
            if not choice:
                return 10
            
            choice = int(choice)
            
            if choice == 1:
                return 10
            elif choice == 2:
                return 20
            elif choice == 3:
                return 30
            elif choice == 4:
                return 50
            elif choice == 5:
                return 100
            elif choice == 6:
                return 9999  # Show all programs
            elif choice == 7:
                while True:
                    try:
                        custom = input("Enter custom number (1-1000): ").strip()
                        custom_num = int(custom)
                        if 1 <= custom_num <= 1000:
                            return custom_num
                        else:
                            print("Please enter a number between 1 and 1000.")
                    except ValueError:
                        print("Please enter a valid number.")
            elif choice == 8:
                print("Goodbye!")
                return -1  # Exit signal
            else:
                print("Please enter a number between 1 and 8.")
                
        except ValueError:
            print("Please enter a valid number.")
        except KeyboardInterrupt:
            print("\nOperation cancelled by user.")
            print("Goodbye!")
            return -1  # Exit signal


def main():
    """Main function to run the BAM parser."""
    try:
        print("="*60)
        print("Windows BAM (Background Activity Moderator) Parser")
        print("="*60)
        
        # Show Windows version info immediately
        build_number = str(windows.system.build_number)
        print(f"Detected Windows Build: {build_number}")
        
        # Get user's choice for number of programs to display
        top_count = get_user_choice()
        
        # Check if user wants to exit
        if top_count == -1:
            return 0  # Clean exit - no analysis needed
        
        # Initialize parser only if user didn't choose to exit
        print("\nInitializing BAM parser...")
        parser = BamParser(log_level=logging.INFO)
        
        # Print summary to console with user's choice
        if top_count == 9999:
            print(f"\nDisplaying ALL recent programs...")
        else:
            print(f"\nDisplaying top {top_count} recent programs...")
            
        parser.print_summary(top_count=top_count)
        
        # Ask if user wants to export to JSON
        print("\n" + "="*60)
        while True:
            try:
                export_choice = input("Do you want to export results to JSON file? (y/n/exit): ").strip().lower()
                
                if export_choice in ['exit', 'e', 'quit', 'q']:
                    print("Goodbye!")
                    return 0
                elif export_choice in ['y', 'yes']:
                    output_file = parser.export_to_json()
                    print(f"Detailed results exported to: {output_file}")
                    break
                elif export_choice in ['n', 'no']:
                    print("Export skipped.")
                    break
                else:
                    print("Please enter 'y' for yes, 'n' for no, or 'exit' to quit.")
                    
            except KeyboardInterrupt:
                print("\nGoodbye!")
                return 0
        
        print("\nAnalysis complete!")
        print("Thank you for using BAM Parser!")
        
    except Exception as e:
        logging.error(f"Parser failed: {e}")
        print(f"Error: {e}")
        return 1
    
    return 0


if __name__ == "__main__":
    exit(main())