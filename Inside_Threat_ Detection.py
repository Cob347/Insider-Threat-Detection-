import pandas as pd
from datetime import datetime, timedelta
import numpy as np
import logging

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def identify_insider_threats(access_logs_file, sensitive_events, lateral_threshold=5, start_date=None, end_date=None, threshold_factor=3):
    """
    Identifies potential insider threats based on access logs.

    Parameters:
    access_logs_file (str): Path to the CSV file containing access logs.
    sensitive_events (list): List of sensitive event types to monitor.
    lateral_threshold (int, optional): Minimum number of different systems accessed in a short period for lateral movement. Defaults to 5.
    start_date (datetime, optional): Start date for filtering logs. Defaults to 2022-01-01.
    end_date (datetime, optional): End date for filtering logs. Defaults to 2022-07-01.
    threshold_factor (int, optional): Factor for setting the abnormal activity threshold. Defaults to 3.

    Returns:
    pd.DataFrame: DataFrame containing incidents of suspected insider threats or None if no data found.
    """
    if not access_logs_file or not sensitive_events:
        logging.error("Invalid input parameters.")
        return None

    try:
        logging.info("Loading access logs...")
        access_logs = pd.read_csv(access_logs_file)

        logging.info("Converting eventtime to datetime...")
        access_logs['eventtime'] = pd.to_datetime(access_logs['eventtime'])

        if start_date is None:
            start_date = datetime(2022, 1, 1)
        if end_date is None:
            end_date = datetime(2022, 7, 1)

        logging.info("Filtering access logs for the specified time period...")
        access_logs = access_logs[(access_logs['eventtime'] >= start_date) & (access_logs['eventtime'] < end_date)]

        logging.info("Counting occurrences of sensitive events...")
        user_sensitive_event_counts = access_logs[access_logs['eventtype'].isin(sensitive_events)] \
            .groupby('useridentity')['eventtype'].count()

        if not user_sensitive_event_counts.empty:
            threshold = user_sensitive_event_counts.mean() + threshold_factor * user_sensitive_event_counts.std()
            logging.info(f"Calculated threshold for abnormal activity: {threshold}")

            suspected_insiders = user_sensitive_event_counts[user_sensitive_event_counts > threshold]

            logging.info("Checking for lateral movement patterns...")
            lateral_movements = access_logs.groupby('useridentity').apply(
                lambda df: df.set_index('eventtime').resample('1H')['system'].nunique().max()
            )
            lateral_movement_suspects = lateral_movements[lateral_movements >= lateral_threshold]

            combined_suspects = suspected_insiders.index.intersection(lateral_movement_suspects.index)
            if not combined_suspects.empty:
                incidents = access_logs[access_logs['useridentity'].isin(combined_suspects)]
                incidents_sorted = incidents.sort_values(by=['useridentity', 'eventtime'])
                return incidents_sorted
            else:
                return None
        else:
            logging.info("No sensitive events found in the logs.")
            return None
            
    except FileNotFoundError:
        logging.error(f"File '{access_logs_file}' not found. Please provide a valid file path.")
        return None
    except pd.errors.EmptyDataError:
        logging.error("The access logs file is empty or contains no data.")
        return None
    except KeyError as e:
        logging.error(f"Column '{e}' not found in access logs. Please check the file structure.")
        return None
    except Exception as e:
        logging.error("An error occurred:", e)
        return None

# Replace 'your_real_access_logs.csv' with the path to your actual access logs file
access_logs_file = 'your_real_access_logs.csv'

# Identify potential insider threats
sensitive_events = ['sensitive_read', 'sensitive_write']
suspected_insiders = identify_insider_threats(access_logs_file, sensitive_events)

if suspected_insiders is not None:
    logging.info("Suspected insiders detected:")
    print(suspected_insiders)
else:
    logging.info("No suspected insiders detected.")
