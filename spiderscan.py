import os
import subprocess
import sys
import logging
import argparse
import concurrent.futures
import yaml
from pathlib import Path
from retrying import retry

# Setup logging
def setup_logging():
    """Set up logging configuration."""
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("spiderscan.log"),
            logging.StreamHandler()
        ]
    )

# Display banner
def banner():
    """Print banner for SpiderScan."""
    print("""
   _____ _            _        _____             _            
  / ____| |          | |      / ____|           | |           
 | (___ | |_ __ _ ___| |_ ___| (___   ___  _ __ | |_ ___  _ __ 
  \___ \| __/ _` / __| __/ _ \\___ \ / _ \| '_ \| __/ _ \| '__|
  ____) | || (_| \__ \ ||  __/____) | (_) | | | | || (_) | |   
 |_____/ \__\__,_|___/\__\___|_____/ \___/|_| |_|\__\___/|_|   
                                                                  
    Created by Muhammad Waseem
    """)
    logging.info("SpiderScan started.")

# Retry decorator for commands
@retry(stop_max_attempt_number=3, wait_fixed=5000)
def run_command(command, cwd=None):
    """Run a shell command and handle errors with retries."""
    try:
        logging.info(f"Running command: {command}")
        result = subprocess.run(command, shell=True, cwd=cwd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        logging.info(result.stdout.decode())
    except subprocess.CalledProcessError as e:
        logging.error(f"Error occurred while running command: {e}")
        logging.error(e.stderr.decode())
        raise

def check_dependency(command, install_command):
    """Check if a command-line tool is installed and install if not."""
    if subprocess.call(command, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        logging.info(f"{command} not found. Installing...")
        run_command(install_command)

def clone_repo(repo_url, clone_dir):
    """Clone a Git repository if it does not exist."""
    if not Path(clone_dir).exists():
        run_command(f'git clone {repo_url} {clone_dir}')
    else:
        logging.info(f"Repository {clone_dir} already exists.")

def collect_urls(domain, output_dir):
    """Collect URLs using ParamSpider and save them in a text file."""
    logging.info(f"Collecting URLs for domain: {domain}")
    temp_file = 'temp_urls.txt'
    run_command(f'python ParamSpider/paramspider.py -d {domain} -o {temp_file}')
    
    # Read URLs from temp file and save them in text format
    urls = []
    with open(temp_file, 'r') as file:
        urls = file.readlines()
    
    txt_file = Path(output_dir) / 'urls.txt'
    with open(txt_file, 'w') as file:
        file.writelines(urls)

    os.remove(temp_file)
    logging.info(f"URLs saved to {txt_file}")

def run_nuclei(url_file, template_dir):
    """Run Nuclei with the collected URLs and templates."""
    logging.info(f"Running Nuclei with templates from: {template_dir}")

    # Ensure the URL file exists
    if not Path(url_file).exists():
        logging.error(f"URL file not found: {url_file}")
        raise FileNotFoundError(f"URL file not found: {url_file}")

    # Ensure the template directory exists
    if not Path(template_dir).exists():
        logging.error(f"Template directory not found: {template_dir}")
        raise FileNotFoundError(f"Template directory not found: {template_dir}")

    # Run Nuclei command
    command = f'nuclei -l {url_file} -t {template_dir}'
    run_command(command)

def process_target(domain, output_dir, templates_dir):
    """Main processing function."""
    # Ensure output directory exists
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    
    # Clone repositories and install dependencies
    clone_repo('https://github.com/0xKayala/ParamSpider.git', 'ParamSpider')
    run_command('pip install -r ParamSpider/requirements.txt')
    clone_repo('https://github.com/MuhammadWaseem29/Fuzzingtemplates-.git', templates_dir)
    check_dependency('nuclei -version', 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest')
    
    # Collect URLs and run Nuclei
    with concurrent.futures.ThreadPoolExecutor() as executor:
        future_collect = executor.submit(collect_urls, domain, output_dir)
        future_collect.result()  # Ensure collection is complete before proceeding
        
        txt_file = Path(output_dir) / 'urls.txt'
        future_nuclei = executor.submit(run_nuclei, txt_file, templates_dir)
        future_nuclei.result()  # Wait for Nuclei scan to complete

def main():
    # Setup
    setup_logging()
    banner()

    # Parse arguments
    parser = argparse.ArgumentParser(description='SpiderScan - A powerful URL scanning tool.')
    parser.add_argument('-d', '--domain', required=True, help='Domain to scan (e.g., example.com)')
    parser.add_argument('-o', '--output-dir', default='output', help='Directory for saving collected URLs')
    parser.add_argument('-t', '--templates', default='Fuzzingtemplates-/', help='Path to Nuclei templates')
    args = parser.parse_args()

    # Run the processing
    try:
        process_target(args.domain, args.output_dir, args.templates)
        logging.info("SpiderScan completed successfully.")
    except Exception as e:
        logging.error(f"SpiderScan encountered an error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
