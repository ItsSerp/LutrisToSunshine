import os
from typing import Optional, List, Tuple
from utils.utils import run_command, parse_json_output

def get_lutris_command(args: str = "") -> Optional[str]:
    """Get the appropriate Lutris command based on installation type."""
    # Check for Flatpak installation
    if run_command("flatpak list | grep net.lutris.Lutris").returncode == 0:
        base_cmd = "flatpak run net.lutris.Lutris"
    # Check for native installation
    elif run_command("which lutris").returncode == 0:
        base_cmd = "lutris"
    else:
        return None

    return f"{base_cmd} {args}".strip()

def is_lutris_running() -> bool:
    """Check if Lutris is currently running."""
    our_script_name = os.path.basename(__file__)
    cmd = f"ps aux | grep -v grep | grep -v {our_script_name} | grep -E " + r"'(^|\s)lutris($|\s)|net\.lutris\.Lutris'"
    result = run_command(cmd)
    return result.returncode == 0 and result.stdout.strip() != b''

def list_lutris_games() -> List[Tuple[str, str]]:
    """List all games in Lutris."""
    lutris_cmd = get_lutris_command()
    cmd = f"{lutris_cmd} -lo --json"
    result = run_command(cmd)
    games = parse_json_output(result)
    return [(game['id'], game['name']) for game in games if game.get('runner') != 'steam'] if games else []

def generate_lutris_script(game_id: str) -> Optional[str]:
    """Generate a bash script for launching a Lutris game.
    
    Args:
        game_id: The Lutris game ID
        
    Returns:
        The path to the generated script, or None if generation failed
    """
    # Ensure the scripts directory exists
    scripts_dir = os.path.expanduser("~/Games/scripts")
    os.makedirs(scripts_dir, exist_ok=True)
    
    script_path = os.path.join(scripts_dir, f"{game_id}.sh")
    
    # Get the Lutris command
    lutris_cmd = get_lutris_command()
    if not lutris_cmd:
        return None
    
    # Run lutris -b to generate the bash script
    cmd = f"{lutris_cmd} -b {script_path} {game_id}"
    result = run_command(cmd)
    
    if result.returncode == 0 and os.path.exists(script_path):
        # Make the script executable
        os.chmod(script_path, 0o755)
        return script_path
    else:
        print(f"Warning: Failed to generate Lutris script for game ID {game_id}")
        return None
