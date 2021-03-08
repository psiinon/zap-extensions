package org.zaproxy.addon.automation.jobs;

import java.util.Collection;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.Plugin;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.addon.automation.jobs.ActiveScanJobResultData.RuleData;
import org.zaproxy.zap.extension.ascan.ActiveScan;
import org.zaproxy.zap.extension.pscan.PluginPassiveScanner;
import org.zaproxy.zap.extension.stats.ExtensionStats;
import org.zaproxy.zap.extension.stats.InMemoryStats;

public class PassiveScanJobResultData extends JobResultData {
	
	private Map<Integer, RuleData> ruleDataMap = new HashMap<>();

	public PassiveScanJobResultData(String jobName, List<PluginPassiveScanner> list) {
		super(jobName);
		        
        ExtensionStats extStats =
                Control.getSingleton()
                .getExtensionLoader()
                .getExtension(ExtensionStats.class);

        InMemoryStats stats = null;
        if (extStats != null) {
			stats = extStats.getInMemoryStats();
		}

        RuleData data;
		for (PluginPassiveScanner scanner : list) {
			data = new RuleData(scanner);
			ruleDataMap.put(data.getId(), data);
			if (stats != null) {
				data.setTimeTakenMs(stats.getStat("stats.pscan." + data.name));
			}
		}
	}

	
	public RuleData getRuleData(int ruleId) {
		return ruleDataMap.get(ruleId);
	}
	
	public Collection<RuleData> getAllRuleData() {
		return ruleDataMap.values();
	}

	@Override
	public String getKey() {
		return "passiveScanData";
	}
	
	public class RuleData {
		private int id;
		private String name;
		private long timeTakenMs = 0;
		private Plugin.AlertThreshold threshold;
				
		public RuleData(PluginPassiveScanner scanner) {
			this.id = scanner.getPluginId();
			this.name = scanner.getName();
			this.threshold = scanner.getAlertThreshold();
		}
		
		public Plugin.AlertThreshold getThreshold() {
			return threshold;
		}

		public int getId() {
			return id;
		}

		public String getName() {
			return name;
		}
		
		public void setTimeTakenMs(Long timeTakenMs) {
			if (timeTakenMs != null) {
				this.timeTakenMs = timeTakenMs;
			}
		}

		public long getTimeTakenMs() {
			return timeTakenMs;
		}
		
	}

}
