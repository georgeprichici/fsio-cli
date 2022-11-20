import asyncio
import time
import json
from filescan_cli.core.logger import Logger
from filescan_cli.service.scan import Scan
from filescan_cli.service.report import Report
from filescan_cli.formatter.reports import ReportsFormatter


class MDCoreScanFlow:
    """Scanning flow"""

    def __init__(self):
        self.logger = Logger()
        self.scanner = Scan()
        self.report = Report()
        self.formatter = ReportsFormatter()


    async def run(
        self,
        file,
        link,
        desc,
        tags,
        prop_tags,
        password,
        is_private
    ):
        """Upload a file or link and receive its report"""

        scan_id = await self.__upload(file, link, desc, tags, prop_tags,password, is_private)
        mdcore_response = await self.__get_scan_reports(scan_id)

        return mdcore_response


    async def __upload(self, file, link, desc, tags, prop_tags, password, is_private):

        result = await self.scanner.upload(file, link, desc, tags, prop_tags,password, is_private)

        if 'error' in result:            
            return

        response = result['content']
        if 'flow_id' not in response:
            return

        return response['flow_id']


    async def __get_scan_reports(self, scan_id):
        """Get reports related to scan"""


        while True:
            await asyncio.sleep(1)

            result = await self.report.get_scan_reports(scan_id, filters=['finalVerdict'])
            if 'error' in result:
                return

            scan_report = result['content']
            if 'reports' not in scan_report or not scan_report['reports']:
                continue
            
            # TODO: 
            #   check which is last state??
            #   missing created date for finalVerdict -> use another filter?
            #   {
            #     "reports": {
            #         "<<<id>>>": {
            #         "finalVerdict": {
            #             "verdict": "INFORMATIONAL",
            #             "threatLevel": 0.2,
            #             "confidence": 1
            #         }
            #         }
            #     }
            #   }
            #        


            '''
            Processing result and its index
                No Threat Detected: 0
                Infected: 1
                Suspicious: 2
                Failed: 3
            '''            

            # TODO: when is unknown status being used? 
            mdcore_response = { }
            possible_scan_results = {
                "informational": 0,
                "malicious": 1,
                "suspicious": 2,
                "likely_malicious": 1,
                "unknown": 3  
            }


            reports = scan_report['reports']            
            for id, report in reports.items():
                
                # self.logger.debug("Report: \n" + json.dumps(report, indent=3))
                # report = reports[id]
                if 'finalVerdict' not in report:
                    continue
                
                mdcore_response["def_time"] = int(time.time() * 1000) # TODO get report time

                final_verdict = report["finalVerdict"]
                
                mdcore_response["scan_result_i"] = possible_scan_results[str(final_verdict["verdict"]).lower()]
                mdcore_response["threat_found"] = f"{final_verdict['verdict'].capitalize()} ThreatLevel: {final_verdict['threatLevel']:.0%}"
                
            return mdcore_response

