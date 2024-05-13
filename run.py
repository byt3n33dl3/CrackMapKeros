from os import mkdir
from os.path import exists
from os.path import join as path_join
import shutil
from mce import PATH, PATH, PATH, PATH
from mce import initialize_db
from mce import nxc_logger


def first_run_setup(logger=nxc_logger):
    if not exists(PATH):
        mkdir(PATH)

    if not exists(PATH):
        logger.display("First time use detected")
        logger.display("Creating home directory structure")
        mkdir(PATH)

    folders = (
        "logs",
        "modules",
        "protocols",
        "workspaces",
        "obfuscated_scripts",
        "screenshots",
    )
    for folder in folders:
        if not exists(path_join(PATH, folder)):
            logger.display(f"Creating missing folder {folder}")
            mkdir(path_join(PATH, folder))

    initialize_db()

    if not exists(CONFIG_PATH):
        logger.display("Copying default configuration file")
        default_path = path_join(DATA_PATH, "nxc.conf")
        shutil.copy(default_path, PATH)