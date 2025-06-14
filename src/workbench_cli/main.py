import sys
import time
import logging
import argparse
from typing import Optional

# Import from other modules in the package
from .cli import parse_cmdline_args
from .api import WorkbenchAPI
from . import handlers
from .utils import format_duration, _format_and_print_error
from .exceptions import (
    WorkbenchCLIError,
    ApiError,
    NetworkError,
    ConfigurationError,
    AuthenticationError,
    ProcessError,
    ProcessTimeoutError,
    FileSystemError,
    ValidationError,
    CompatibilityError,
    ProjectNotFoundError,
    ScanNotFoundError
)


def main() -> int:
    """
    Main function to parse arguments, set up logging, initialize the API client,
    and dispatch to the appropriate command handler.
    Returns an exit code (0 for success, non-zero for failure).
    """
    start_time = time.monotonic()
    exit_code = 1 # Default to failure
    logger = None # Initialize logger variable

    try:
        params = parse_cmdline_args()

        # Setup logging
        log_level = getattr(logging, params.log.upper(), logging.INFO)
        # Configure file handler (overwrite mode) and stream handler
        logging.basicConfig(level=log_level,
                            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
                            handlers=[logging.FileHandler("workbench-cli-log.txt", mode='w')],
                            force=True) # Use force=True to allow reconfiguration if run multiple times

        # Add console handler separately to control its level independently
        console_handler = logging.StreamHandler(sys.stdout)
        console_formatter = logging.Formatter('%(levelname)s: %(message)s') # Simpler format for console
        console_handler.setFormatter(console_formatter)
        console_handler.setLevel(logging.INFO if log_level <= logging.INFO else log_level)
        logging.getLogger().addHandler(console_handler)

        logger = logging.getLogger("workbench-cli")

        # Print Configuration for this Run
        print("--- Workbench CLI Configuration ---")
        print(f"Command: {params.command}")
        for k, v in sorted(params.__dict__.items()):
            if k == 'command': continue
            display_val = v
            if k == 'api_token' and params.log.upper() != 'DEBUG':
                 display_val = "****" if v else "Not Set"
            print(f"  {k:<30} = {display_val}")
        print("------------------------------------")
        logger.debug("Parsed parameters: %s", params)

        # Initialize Workbench API client
        try:
            workbench = WorkbenchAPI(params.api_url, params.api_user, params.api_token)
            logger.info("Workbench client initialized.")
        except AuthenticationError as e:
            print(f"\nAuthentication Error: {e.message}")
            logger.error("Failed to authenticate with Workbench", exc_info=True)
            return 1
        except NetworkError as e:
            print(f"\nNetwork Error: {e.message}")
            logger.error("Failed to connect to Workbench", exc_info=True)
            return 1
        except Exception as e:
            print(f"\nError initializing Workbench connection: {e}")
            logger.critical("Failed to initialize Workbench connection", exc_info=True)
            return 1

        # --- Command Dispatch ---
        COMMAND_HANDLERS = {
            "scan": handlers.handle_scan,
            "import-da": handlers.handle_import_da,
            "show-results": handlers.handle_show_results,
            "evaluate-gates": handlers.handle_evaluate_gates,
            "download-reports": handlers.handle_download_reports,
            "scan-git": handlers.handle_scan_git,
        }

        handler = COMMAND_HANDLERS.get(params.command)

        if handler:
            # Execute the command handler
            result = handler(workbench, params) # Handlers raise exceptions on failure

            # Determine exit code based on command and result
            if params.command == 'evaluate-gates':
                # evaluate-gates returns True for PASS, False for FAIL
                exit_code = 0 if result else 1
                if exit_code == 0:
                    print("\nWorkbench CLI finished successfully (Gates Passed).")
                else:
                    # Don't print 'Error' here, just the status
                    print("\nWorkbench CLI finished (Gates FAILED).")
            else:
                # For other commands, success is assumed if no exception was raised
                exit_code = 0
                print("\nWorkbench CLI finished successfully.")

        else:
            # This case should ideally be caught by argparse, but handle defensively
            print(f"Error: Unknown command '{params.command}'.")
            logger.error(f"Unknown command '{params.command}' encountered in main dispatch.")
            exit_code = 1 # Failure

    # --- Unified Exception Handling ---
    except (ConfigurationError, ValidationError, CompatibilityError) as e:
        # Errors typically due to user input/setup, less need for full traceback in log
        print(f"\nConfiguration/Validation Error: {e.message}")
        if logger: logger.error("%s: %s", type(e).__name__, e.message, exc_info=False)
        exit_code = 1
    except (ApiError, NetworkError, ProcessError, ProcessTimeoutError, FileSystemError) as e:
        # Errors during runtime interaction, traceback can be useful
        print(f"\nRuntime Error: {e.message}")
        if logger: logger.error("%s: %s", type(e).__name__, e.message, exc_info=True)
        exit_code = 1
    except WorkbenchCLIError as e:
        # Catch any other specific CLI errors that might be missed above
        print(f"\nWorkbench CLI Error: {e.message}")
        if logger: logger.error("Unhandled WorkbenchCLIError: %s", e.message, exc_info=True)
        exit_code = 1
    except Exception as e:
        # Catch truly unexpected errors
        print(f"\nUnexpected Error: {e}")
        if logger: logger.critical("Unexpected error occurred", exc_info=True)
        exit_code = 1
    finally:
        # Calculate and print duration regardless of success/failure
        end_time = time.monotonic()
        duration_seconds = end_time - start_time
        # Use the static method from Workbench class for formatting
        duration_str = format_duration(duration_seconds)
        print(f"\nTotal Execution Time: {duration_str}")
        if logger: logger.info("Total execution time: %s", duration_str)

    return exit_code
