import time
import json

class MDCoreReportsFormatter:

    def __init__(self):
        pass

    def empty_result(self):
        result = {
            "def_time": int(time.time() * 1000),
            "scan_result_i": 10, # Not Scanned
            "threat_found": ""
        }

        return result

        
    def format(self, reports, total = -1):
        
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
               
        for id, report in reports.items():                        
            # report = reports[id]
            if 'finalVerdict' not in report:
                continue

            if 'overallState' not in report or not report['overallState']:
                continue       

            accepted_states = ['success', 'success_partial', 'failed', 'failed_partial']
            if report['overallState'].lower() not in accepted_states:
                continue        
            
            mdcore_response["def_time"] = int(time.time() * 1000) # TODO get report time

            final_verdict = report["finalVerdict"]
            
            mdcore_response["scan_result_i"] = possible_scan_results[str(final_verdict["verdict"]).lower()]
            mdcore_response["threat_found"] = f"{final_verdict['verdict'].capitalize()}"

        return mdcore_response