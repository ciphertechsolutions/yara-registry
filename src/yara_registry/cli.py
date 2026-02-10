import argparse
from pathlib import Path
import shutil
import platformdirs
import logging

logger = logging.getLogger(__name__)

parser = argparse.ArgumentParser()
parser.add_argument("namespace", type=str, help="Scope of rules, this should be considered equivalent to python package name, so ensure it does not conflict ('-', and '_' are considered interchangeable in package naming.)")
parser.add_argument("path", type=str, help="Path to directory containing rules, files must end in '.yar' or '.yara'")

def main():
    args = parser.parse_args()
    namespace = args.namespace
    path = Path(args.path)
    data_dir = Path(platformdirs.user_data_dir("yara_registry", appauthor=False))
    logger.info(f"Installing rules to {data_dir}")
    rules_namespace_path = data_dir / "rules" / namespace
    shutil.copytree(path, rules_namespace_path, dirs_exist_ok=True)

if __name__ == "__main__":
    main()