import asyncio
from filescan_cli.core.logger import Logger
from filescan_cli.service.scan import Scan
from filescan_cli.service.report import Report
from filescan_cli.formatter.mdcore_reports import MDCoreReportsFormatter
import json

class MDCoreScanFlow:
    """Scanning flow"""

    def __init__(self):
        self.logger = Logger()
        self.scanner = Scan()
        self.report = Report()
        self.formatter = MDCoreReportsFormatter()


    async def run(
        self,
        file,
        link,
        desc,
        tags,
        prop_tags,
        password,
        is_private, 
        filename
    ):
        """Upload a file or link and receive its report"""

        scan_id = await self.__upload(file, link, desc, tags, prop_tags,password, is_private, filename)
        mdcore_response = await self.__get_scan_reports(scan_id)

        return mdcore_response


    async def __upload(self, file, link, desc, tags, prop_tags, password, is_private, filename):

        result = await self.scanner.upload(file, link, desc, tags, prop_tags,password, is_private, filename)

        if 'error' in result:            
            return

        response = result['content']
        if 'flow_id' not in response:
            return
        # self.logger.error(f"report id: {response['flow_id']}")
        return response['flow_id']


    async def __get_scan_reports(self, scan_id):
        """Get reports related to scan"""

        while True:
            await asyncio.sleep(1)

            result = await self.report.get_scan_reports(scan_id, filters=['finalVerdict', 'overallState'])
            if 'error' in result:
                return
            
            scan_report = result['content']
            
            if 'reports' not in scan_report or not scan_report['reports']:
                continue
                        
            reports = scan_report['reports']                              
                
            mdcore_result =  self.formatter.format(reports)

            if not mdcore_result:
                continue
            else:
                return mdcore_result

