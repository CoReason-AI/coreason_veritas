import logging
import os
import sys
import time
from loguru import logger
from src.coreason_veritas.logging_utils import configure_logging

def verify_logging():
    # 1. Initialize Configuration
    configure_logging()

    # 2. Test Direct Loguru Usage
    logger.info("Test Info Log from Loguru")
    logger.debug("Test Debug Log from Loguru")

    # 3. Test Exception Capture
    try:
        1 / 0
    except ZeroDivisionError:
        logger.exception("Test Exception from Loguru")

    # 4. Test Standard Library Interception
    logging.getLogger("test_standard_lib").info("Test Info Log from Standard Logging")
    logging.getLogger("test_standard_lib").warning("Test Warning Log from Standard Logging")

    # Force flush for enqueued logs
    logger.complete()
    # Give a brief moment for FS (though complete() should be enough)
    time.sleep(0.5)

    # 5. Verify File Creation
    log_file = "logs/app.log"
    if os.path.exists(log_file):
        print(f"SUCCESS: Log file created at {log_file}")
        with open(log_file, "r") as f:
            content = f.read()
            # print("--- Log File Content ---")
            # print(content)
            # print("----------------------")

            # Basic content checks
            if "Test Info Log from Loguru" in content:
                print("SUCCESS: Loguru Info found in file.")
            else:
                print("FAILURE: Loguru Info NOT found in file.")

            if "Test Exception from Loguru" in content:
                print("SUCCESS: Loguru Exception found in file.")
            else:
                print("FAILURE: Loguru Exception NOT found in file.")

            if "Test Info Log from Standard Logging" in content:
                print("SUCCESS: Standard Logging Info found in file (Interception working).")
            else:
                print("FAILURE: Standard Logging Info NOT found in file.")
    else:
        print(f"FAILURE: Log file NOT created at {log_file}")

if __name__ == "__main__":
    verify_logging()
