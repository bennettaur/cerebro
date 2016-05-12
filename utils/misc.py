import logging
import os

__author__ = 'bennettaur'


def setup_logging(name, add_console=False):
    log_dir = "logs"
    log_format = '%(asctime)s--%(name)s--%(levelname)s: %(message)s'
    date_format = '%m/%d/%Y %I:%M:%S %p'
    formatter = logging.Formatter(log_format, date_format)

    logging_level = logging.DEBUG

    logger = logging.getLogger(name)
    logger.setLevel(logging_level)

    log_file = os.path.join(log_dir, name + ".log")
    file_handler = logging.FileHandler(filename=log_file)
    file_handler.setFormatter(formatter)
    file_handler.setLevel(logging_level)
    logger.addHandler(file_handler)

    if add_console:
        console = logging.StreamHandler()
        console.setFormatter(formatter)
        console.setLevel(logging_level)
        logger.addHandler(console)

    return logger


def add_file_handlers_to_tornado_logs(logs=("tornado.access", "tornado.application", "tornado.general")):
    log_dir = "logs"
    log_format = '%(asctime)s--%(name)s--%(levelname)s: %(message)s'
    date_format = '%m/%d/%Y %I:%M:%S %p'
    formatter = logging.Formatter(log_format, date_format)

    logging_level = logging.DEBUG

    for log in logs:
        logger = logging.getLogger(log)
        logger.setLevel(logging_level)

        log_file = os.path.join(log_dir, log + ".log")
        file_handler = logging.FileHandler(filename=log_file)
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging_level)
        logger.addHandler(file_handler)
