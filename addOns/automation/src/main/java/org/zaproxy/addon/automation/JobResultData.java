package org.zaproxy.addon.automation;

public abstract class JobResultData {

	private String jobName;
	
	public JobResultData(String jobName) {
		this.jobName = jobName;
	}
	
	public String getJobName() {
		return jobName;
	}

	public abstract String getKey();
	
}
