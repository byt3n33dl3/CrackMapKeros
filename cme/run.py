from os import mkdir
from os.path import exists
from os.path import join as path_join
import shutil
from cme.paths import CME_PATH, CONFIG_PATH, TMP_PATH, DATA_PATH
from cme.cmedb import initialize_db
from cme.logger import cme_logger


def first_run_setup(logger=cme_logger):
    if not exists(TMP_PATH):
        mkdir(TMP_PATH)

    if not exists(CME_PATH):
        logger.display("First time use detected")
        logger.display("Creating home directory structure")
        mkdir(CME_PATH)

    folders = (
        "logs",
        "modules",
        "protocols",
        "workspaces",
        "obfuscated_scripts",
        "screenshots",
    )
    for folder in folders:
        if not exists(path_join(CME_PATH, folder)):
            logger.display(f"Creating missing folder {folder}")
            mkdir(path_join(CME_PATH, folder))

    initialize_db(logger)

    if not exists(CONFIG_PATH):
        logger.display("Copying default configuration file")
        default_path = path_join(DATA_PATH, "cme.conf")
        shutil.copy(default_path, CME_PATH)