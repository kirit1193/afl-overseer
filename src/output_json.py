"""JSON output formatter."""

import json
import time
from pathlib import Path
from typing import List

from .models import FuzzerStats, CampaignSummary, MonitorConfig
from .utils import get_timestamp
import logging

logger = logging.getLogger(__name__)


class JSONOutput:
    """JSON output formatter."""

    def __init__(self, config: MonitorConfig):
        self.config = config

    def write_output(
        self,
        all_stats: List[FuzzerStats],
        summary: CampaignSummary,
        system_info: dict = None
    ):
        """Write statistics to JSON file."""
        if not self.config.json_file:
            return

        try:
            output_data = self._create_output_dict(all_stats, summary, system_info)

            # Write to file
            with open(self.config.json_file, 'w') as f:
                json.dump(output_data, f, indent=2)

            logger.info(f"JSON output written to {self.config.json_file}")

        except Exception as e:
            logger.error(f"Error writing JSON output: {e}")

    def _create_output_dict(
        self,
        all_stats: List[FuzzerStats],
        summary: CampaignSummary,
        system_info: dict = None
    ) -> dict:
        """Create output dictionary."""
        return {
            'metadata': {
                'timestamp': int(time.time()),
                'timestamp_str': get_timestamp(),
                'monitor_version': '2.0',
                'findings_directory': str(self.config.findings_dir),
            },
            'summary': summary.to_dict(),
            'fuzzers': [stats.to_dict() for stats in all_stats],
            'system': system_info or {},
        }

    @staticmethod
    def write_compact(file_path: Path, data: dict):
        """Write compact JSON without indentation."""
        with open(file_path, 'w') as f:
            json.dump(data, f, separators=(',', ':'))

    @staticmethod
    def read_json(file_path: Path) -> dict:
        """Read JSON file."""
        try:
            with open(file_path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Error reading JSON file {file_path}: {e}")
            return {}
