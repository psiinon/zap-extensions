package org.zaproxy.addon.automation.jobs;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import org.parosproxy.paros.core.scanner.HostProcess;
import org.parosproxy.paros.core.scanner.Plugin;
import org.zaproxy.addon.automation.JobResultData;
import org.zaproxy.zap.extension.ascan.ActiveScan;

public class ActiveScanJobResultData extends JobResultData {
	
	private Map<Integer, RuleData> ruleDataMap = new HashMap<>();

	public ActiveScanJobResultData(String jobName, ActiveScan activeScan) {
		super(jobName);
		
		RuleData data;
		for (HostProcess hp : activeScan.getHostProcesses()) {
			for (Plugin plugin : hp.getRunning()) {
				data = ruleDataMap.computeIfAbsent(plugin.getId(), k -> new RuleData(plugin.getId(), plugin.getName()));
				data.incTimeTakenMs(plugin.getTimeStarted().getTime() - plugin.getTimeFinished().getTime());
				data.setStrength(plugin.getAttackStrength());
				data.setThreshold(plugin.getAlertThreshold());
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
		return "activeScanData";
	}
	
	public class RuleData {
		private int id;
		private String name;
		private long timeTakenMs = 0;
		private Plugin.AlertThreshold threshold;
		private Plugin.AttackStrength strength;
				
		public RuleData(int id, String name) {
			this.id = id;
			this.name = name;
		}
		
		public void incTimeTakenMs(long time) {
			this.timeTakenMs += time;
		}

		public Plugin.AlertThreshold getThreshold() {
			return threshold;
		}

		public void setThreshold(Plugin.AlertThreshold threshold) {
			this.threshold = threshold;
		}

		public Plugin.AttackStrength getStrength() {
			return strength;
		}

		public void setStrength(Plugin.AttackStrength strength) {
			this.strength = strength;
		}

		public int getId() {
			return id;
		}

		public String getName() {
			return name;
		}

		public long getTimeTakenMs() {
			return timeTakenMs;
		}
		
	}

}
