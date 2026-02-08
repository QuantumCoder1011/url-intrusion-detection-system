import pandas as pd
from scapy.all import rdpcap, IP, TCP, Raw
from typing import List, Dict
import re

class DataIngestion:
    """Handles ingestion and parsing of CSV and PCAP files"""
    
    def __init__(self):
        pass
    
    def process_file(self, filepath: str, file_type: str) -> List[Dict]:
        """
        Process uploaded file and extract URLs
        
        Args:
            filepath: Path to the uploaded file
            file_type: Type of file ('csv' or 'pcap')
            
        Returns:
            List of dictionaries containing URL data
        """
        if file_type == 'csv':
            return self._process_csv(filepath)
        elif file_type == 'pcap':
            return self._process_pcap(filepath)
        else:
            raise ValueError(f"Unsupported file type: {file_type}")
    
    def _process_csv(self, filepath: str) -> List[Dict]:
        """Extract URLs from CSV log file"""
        urls = []
        
        try:
            # Try to read CSV with common delimiters
            df = pd.read_csv(filepath)
            
            # Common column names for URLs in log files
            url_columns = ['url', 'URL', 'request', 'Request', 'path', 'Path', 'uri', 'URI']
            ip_columns = ['ip', 'IP', 'source_ip', 'Source IP', 'client_ip', 'Client IP', 'src_ip']
            time_columns = ['timestamp', 'Timestamp', 'time', 'Time', 'date', 'Date']
            
            url_col = None
            ip_col = None
            time_col = None
            
            # Find URL column
            for col in url_columns:
                if col in df.columns:
                    url_col = col
                    break
            
            # Find IP column
            for col in ip_columns:
                if col in df.columns:
                    ip_col = col
                    break
            
            # Find timestamp column
            for col in time_columns:
                if col in df.columns:
                    time_col = col
                    break
            
            # If no URL column found, try to extract from other columns
            if url_col is None:
                # Try to find URLs in any text column
                for col in df.columns:
                    if df[col].dtype == 'object':  # String type
                        sample = str(df[col].iloc[0]) if len(df) > 0 else ''
                        if 'http' in sample.lower() or '/' in sample:
                            url_col = col
                            break
            
            # Extract URLs
            if url_col:
                for idx, row in df.iterrows():
                    url = str(row[url_col]) if pd.notna(row[url_col]) else ''
                    source_ip = str(row[ip_col]) if ip_col and pd.notna(row.get(ip_col, '')) else 'Unknown'
                    timestamp = str(row[time_col]) if time_col and pd.notna(row.get(time_col, '')) else ''
                    
                    # Extract URL from full request if needed
                    if url and ('http' in url.lower() or url.startswith('/')):
                        # Clean and extract URL
                        url = self._extract_url_from_string(url)
                        if url:
                            urls.append({
                                'url': url,
                                'source_ip': source_ip,
                                'timestamp': timestamp
                            })
            else:
                # If no URL column found, try to extract from all columns
                for idx, row in df.iterrows():
                    for col in df.columns:
                        value = str(row[col]) if pd.notna(row[col]) else ''
                        url = self._extract_url_from_string(value)
                        if url:
                            source_ip = str(row[ip_col]) if ip_col and pd.notna(row.get(ip_col, '')) else 'Unknown'
                            timestamp = str(row[time_col]) if time_col and pd.notna(row.get(time_col, '')) else ''
                            urls.append({
                                'url': url,
                                'source_ip': source_ip,
                                'timestamp': timestamp
                            })
                            break
            
        except Exception as e:
            raise Exception(f"Error processing CSV file: {str(e)}")
        
        return urls
    
    def _process_pcap(self, filepath: str) -> List[Dict]:
        """Extract HTTP URLs from PCAP file"""
        urls = []
        
        try:
            packets = rdpcap(filepath)
            
            for packet in packets:
                # Check if packet has IP and TCP layers
                if IP in packet and TCP in packet:
                    # Check if packet contains HTTP data
                    if Raw in packet:
                        payload = packet[Raw].load
                        
                        # Try to decode as HTTP request
                        try:
                            http_data = payload.decode('utf-8', errors='ignore')
                            
                            # Look for HTTP request lines
                            if http_data.startswith(('GET', 'POST', 'PUT', 'DELETE', 'HEAD', 'OPTIONS')):
                                # Extract URL from HTTP request
                                lines = http_data.split('\n')
                                if lines:
                                    request_line = lines[0].strip()
                                    # Extract URL from request line (e.g., "GET /path?query=value HTTP/1.1")
                                    url_match = re.search(r'(GET|POST|PUT|DELETE|HEAD|OPTIONS)\s+([^\s]+)', request_line)
                                    if url_match:
                                        url = url_match.group(2)
                                        
                                        # Extract source IP
                                        source_ip = packet[IP].src
                                        
                                        # Extract timestamp
                                        timestamp = str(packet.time)
                                        
                                        urls.append({
                                            'url': url,
                                            'source_ip': source_ip,
                                            'timestamp': timestamp
                                        })
                        except (UnicodeDecodeError, AttributeError):
                            continue
                            
        except Exception as e:
            raise Exception(f"Error processing PCAP file: {str(e)}")
        
        return urls
    
    def _extract_url_from_string(self, text: str) -> str:
        """Extract URL from a string that might contain other data"""
        if not text:
            return ''
        
        # Look for HTTP/HTTPS URLs
        http_match = re.search(r'https?://[^\s<>"\'{}|\\^`\[\]]+', text)
        if http_match:
            return http_match.group(0)
        
        # Look for path-like URLs (starting with /)
        path_match = re.search(r'/[^\s<>"\'{}|\\^`\[\]]*', text)
        if path_match:
            return path_match.group(0)
        
        return ''
