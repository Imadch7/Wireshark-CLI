import csv
import datetime 
import regex 
import subprocess

# --- traffic Class ---
# This class represents a single traffic entry parsed from tshark output.
class traffic:
    def __init__(self, id_traffic, time, ip_source, ip_destination, protocol, packets_size, info):
        # *** CORRECTION 1: All arguments must be assigned to instance variables using 'self.' ***
        # Your original code: `id_traffic = self.id_traffic` was reversed.
        # It should assign the passed argument to the instance attribute.
        self.id_traffic = id_traffic
        self.time = time
        self.ip_source = ip_source
        self.ip_destination = ip_destination
        self.protocol = protocol
        # *** CORRECTION 2: Correctly assign packets_size ***
        # Your original code: `packets_size = self.protocol` was incorrect.
        self.packets_size = packets_size
        self.info = info

    # *** CORRECTION 3: All instance methods must have 'self' as the first parameter ***
    # Your original code was missing 'self' in all getter methods.
    def getId_traffic(self):
        return self.id_traffic

    def getIp_source(self):
        return self.ip_source

    def getIp_destination(self):
        return self.ip_destination

    def getProtocol(self):
        return self.protocol

    def getPackets_size(self):
        # *** CORRECTION 4: Refer to the correct instance variable for packets_size ***
        # Your original code: `return self.packet_size` had a typo.
        return self.packets_size

    def getInfo(self):
        return self.info

    def getTime(self):
        return self.time

    def show_Traffic(self):
        # *** CORRECTION 5: All instance variables in f-strings must be prefixed with 'self.' ***
        # Your original code was missing 'self.' for id_traffic, ip_source, etc.
        return f"{self.id_traffic}-FROM : {self.ip_source} TO : {self.ip_destination} PROTOCOL :{self.protocol} size : {self.packets_size} INFO : {self.info}"


# --- extract Class ---
# This class handles the parsing of tshark standard output into traffic objects.
class extract:
    def __init__(self):
        self.traffics = [] # Initialize an empty list to store traffic objects

    # *** CORRECTION 6: Instance method Tshark_Traffic must have 'self' as the first parameter ***
    def Tshark_Traffic(self, stdout):
        """
        Parses raw tshark stdout string into a list of traffic objects.
        Assumes stdout lines follow the format:
        ID TIME IP_SRC -> IP_DEST PROTOCOL PACKET_SIZE INFO
        """
        if not stdout:
            print("Empty stdout provided for parsing.")
            return [] # Return an empty list if there's no data

        lines = stdout.strip().split('\n')
        parsed_traffics = [] # Temporary list for traffic objects parsed in this call

        for line in lines:
            if not line.strip(): # Skip empty lines
                continue

            # *** CORRECTION 7: Adjusted maxsplit for robust parsing of 'info' ***
            # Changed from maxsplit=6 to maxsplit=7 to ensure all parts, especially info, are captured correctly.
            # Example: 1 0.000000000 10.0.2.15 → 3.228.213.54 TCP 54 48976 → 8884 [ACK] Seq=1 Ack=1 Win=31680 Len=0
            # Parts after split (with maxsplit=7):
            # [0] ID, [1] TIME, [2] IP_SRC, [3] '→', [4] IP_DEST, [5] PROTOCOL, [6] PACKET_SIZE, [7+] INFO
            parts = line.split(maxsplit=7)

            # Check if we have enough core parts (ID, Time, Src, Arrow, Dest, Proto, Size)
            if len(parts) < 7:
                print(f"Skipping malformed line (not enough core parts): '{line}'")
                continue

            # *** CORRECTION 8: Added validation for the arrow symbol (parts[3]) ***
            # Ensure the expected separator '→' is present.
            if parts[3] != '→':
                print(f"Skipping malformed line (missing/incorrect arrow): '{line}'")
                continue

            try:
                # Convert ID, Time, and Packet Size to appropriate numerical types
                id_traffic = int(parts[0])
                time_val = float(parts[1]) # Renamed to avoid conflict with datetime module
                ip_source = parts[2]
                ip_destination = parts[4]
                protocol = parts[5]
                packets_size = int(parts[6])

                # Reconstruct the 'info' string from the remaining parts
                info = " ".join(parts[7:]) if len(parts) > 7 else ""

                # Create a new traffic object and add it to our temporary list
                tra_obj = traffic(id_traffic, time_val, ip_source, ip_destination, protocol, packets_size, info)
                parsed_traffics.append(tra_obj)

            except ValueError as e:
                print(f"Error converting data types in line '{line}': {e}")
            except IndexError as e:
                # This should ideally be caught by len(parts) check, but good for robustness
                print(f"Index error (line shorter than expected) in line '{line}': {e}")

        # Add the newly parsed traffic objects to the instance's main list
        self.traffics.extend(parsed_traffics)
        return parsed_traffics # Return the traffics parsed in this specific call

    def get_traffics(self):
        """Returns the list of all traffic objects parsed by this extractor instance."""
        return self.traffics

    def show_all_traffics(self):
        """Prints details of all parsed traffic objects."""
        if not self.traffics:
            print("No traffic data to display.")
            return
        for t in self.traffics:
            print(t.show_Traffic())


# --- create_CSV Function ---
# Note: Function name changed from 'Create_CSV' to 'create_CSV' for Python naming conventions.
def create_CSV(stdout_data): # Parameter name changed for consistency and clarity
    """
    Parses tshark stdout data, converts it into traffic objects,
    and then writes these objects to a CSV file.
    """
    # 1. Generate a file-safe timestamp for the filename
    current_time = datetime.datetime.now()
    # Format: YYYYMMDD_HHMMSS (e.g., 20250625_163000)
    timestamp_str = current_time.strftime("%Y%m%d_%H%M%S")
    filename = f"traffic_data_{timestamp_str}.csv"

    # 2. Create an instance of the extract class
    traffic_extractor = extract()

    # 3. Parse the stdout data into a list of traffic objects
    # Note: Tshark_Traffic adds to internal list, but also returns newly parsed items
    # *** CORRECTION 9: Use the correct parameter name for Tshark_Traffic ***
    # Your original code used `stdout_data` for the function parameter, but `stdout_data` inside the function.
    # It should consistently use the parameter name `stdout_data`.
    extracted_traffics = traffic_extractor.Tshark_Traffic(stdout_data)

    if not extracted_traffics:
        print("No traffic data extracted. CSV file will not be created.")
        return # Return early if no data

    # 4. Write the extracted data to a CSV file
    try:
        # 'w' mode for writing text, newline='' important for CSV to prevent extra rows
        with open(filename, 'w', newline='') as csvfile:
            csv_writer = csv.writer(csvfile)

            # Define and write the header row
            header = [
                "ID", "Time", "Source IP", "Destination IP",
                "Protocol", "Packet Size", "Info"
            ]
            csv_writer.writerow(header)

            # Write each traffic object as a row in the CSV
            for tra in extracted_traffics:
                row = [
                    tra.getId_traffic(),
                    tra.getTime(),
                    tra.getIp_source(),
                    tra.getIp_destination(),
                    tra.getProtocol(),
                    tra.getPackets_size(),
                    tra.getInfo()
                ]
                csv_writer.writerow(row)
        print(f"Successfully created CSV file: {filename}")
    except IOError as e:
        print(f"Error writing CSV file {filename}: {e}")
    except Exception as e:
        print(f"An unexpected error occurred while creating CSV: {e}")


# --- Example Usage (How you would call the function) ---
if __name__ == "__main__":
    # Simulate stdout from a tshark command
    sample_tshark_output = """
1 0.000000000 10.0.2.15 → 3.228.213.54 TCP 54 48976 → 8884 [ACK] Seq=1 Ack=1 Win=31680 Len=0
2 0.000123000 192.168.1.100 → 8.8.8.8 UDP 60 Standard query A www.google.com
3 0.000500000 172.16.0.1 → 10.0.0.5 ICMP 98 Echo (ping) request id=1234, seq=1
4 0.000750000 10.0.2.15 → 10.0.2.16 TCP 66 [PSH, ACK] Seq=1 Ack=1 Win=31680 Len=12, some more info
Invalid Line format here
5 0.001000000 10.0.2.15 → 3.228.213.54 TCP 54 Another packet
"""
    # Call the function with the sample tshark output
    #create_CSV(sample_tshark_output)

    # Example with empty output
    print("\n--- Testing with Empty Output ---")
    #create_CSV("")

    # Example with malformed lines only
    print("\n--- Testing with Only Malformed Lines ---")
    malformed_output = """
This is a bad line
Another bad line without proper format just for testing 
"""
    #create_CSV(malformed_output)
    
    #tshark_command = ["tshark", "-i", "lo", "-c", "10"] # Using 'lo' (loopback) for safer testing
    # If using a specific host filter as in your previous comment:
    tshark_command = ["tshark", "-i", "eth0", "-f", "host 10.0.2.15", "-c", "10"]


    print("\n--- running tshark command ---")
    try:
        result = subprocess.run(
            tshark_command,
            capture_output=True,
            text=True,
            check=True
        )

        tshark_stdout = result.stdout
        if tshark_stdout:
            print("\n--- Creating CSV from actual tshark output ---")
            create_CSV(tshark_stdout)
        else:
            print("tshark command produced no output.")

    except FileNotFoundError:
        print(f"Error: '{tshark_command[0]}' command not found. "
              "Please ensure tshark is installed and in your system's PATH.")
        print("On Linux, you might need to install it with: sudo apt install tshark")
    except subprocess.CalledProcessError as e:
        print(f"Error running tshark command: {e}")
        print(f"Stderr: {e.stderr}")
        print("Please check tshark permissions (e.g., run with sudo) or command syntax.")
    except Exception as e:
        print(f"An unexpected error occurred while trying to run tshark: {e}")

