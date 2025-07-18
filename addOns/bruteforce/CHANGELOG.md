# Changelog
All notable changes to this add-on will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

## Unreleased

### Fixed
- Error logs to always include stack trace.

## [17] - 2025-01-09
### Changed
- Update minimum ZAP version to 2.16.0.

## [16] - 2024-05-07
### Added
- Support for menu weights (Issue 8369).

### Changed
- Update minimum ZAP version to 2.15.0.
- Maintenance changes.

### Fixed
- Help content typos.

## [15] - 2023-10-12
### Changed
- Update minimum ZAP version to 2.14.0.
- Maintenance changes.

## [14] - 2023-07-11
### Changed
- Update minimum ZAP version to 2.13.0.

## [13] - 2023-06-06
### Changed
- Maintenance changes.
- Default number of threads to 2 * processor count.

## [12] - 2022-10-27
### Changed
- Update minimum ZAP version to 2.12.0.
- Maintenance changes.

## [11] - 2021-10-06
### Changed
- Send HTTP messages with ZAP, making use of all its features (e.g. user authentication, custom user-agent, HTTP Sender scripts) (Issues 173 and 3060).
- Now using 2.10 logging infrastructure (Log4j 2.x).
- Maintenance changes.
- Update minimum ZAP version to 2.11.0.

## [10] - 2020-12-15

### Added
- Added option and functionality to find files without extension. (Issue 5883)

### Changed
- Update minimum ZAP version to 2.10.0.
- Ensure requests are counted and progress updated (Issue 5437).
- Updated owasp.org references (Issue 5962).

## [9] - 2020-01-17
### Changed
- Now targets ZAP 2.8.0.
- Fix un-handled exception when base request doesn't end in a slash (Issue 5435).
- Split up the functionality from the desktop UI and provide external access (Issue 2848)
- Updated addon to use log4j instead of stdout (Issue 5530)
- Log exceptions instead of printing to stderr (Issue 5564).
- Address UI hang.

### Added
- Table export button.
- Add info and repo URLs.

## [8] - 2019-06-07

- Two new options are provided as part of issue 173:
  - One option allows the user to specify the file extensions to ignore.
  URIs ending with specified file extensions are ignored from making requests to the server.
  - The other option allows the user to specify fail case string.
- Inform of running scans (e.g. on session change, add-on uninstall).
- Issue 2000 - Updated strings shown in attack menu with title caps.
- Enable start button on file selection.

## 7 - 2017-11-27

- Code changes for Java 9 (Issue 2602).
- Updated for 2.7.0.

## 6 - 2017-04-03

- Allow to set higher number of threads (Issue 2912).
- Fix issue with multiple concurrent scans.

## 5 - 2015-12-04

- Adding request count on Forced browser tab as specified on issue #1873

## 4 - 2015-09-07

- Change active Pause Button to a Play button (Issue 1802).

## 3 - 2015-08-23

- Minor code changes.
- Corrected the location from where default files are read (Issue 1700).
- Do not access view components when view is not initialised (Issue 1617).

## 2 - 2015-04-13

- Removed DirBuster's GUI code, it's controlled with ZAP's GUI.
- Unload all components during uninstallation (Issue 1505).
- Updated for ZAP 2.4

## 1 - 2014-04-10

- First release as an add-on, previously bundled with ZAP core.

[17]: https://github.com/zaproxy/zap-extensions/releases/bruteforce-v17
[16]: https://github.com/zaproxy/zap-extensions/releases/bruteforce-v16
[15]: https://github.com/zaproxy/zap-extensions/releases/bruteforce-v15
[14]: https://github.com/zaproxy/zap-extensions/releases/bruteforce-v14
[13]: https://github.com/zaproxy/zap-extensions/releases/bruteforce-v13
[12]: https://github.com/zaproxy/zap-extensions/releases/bruteforce-v12
[11]: https://github.com/zaproxy/zap-extensions/releases/bruteforce-v11
[10]: https://github.com/zaproxy/zap-extensions/releases/bruteforce-v10
[9]: https://github.com/zaproxy/zap-extensions/releases/bruteforce-v9
[8]: https://github.com/zaproxy/zap-extensions/releases/bruteforce-v8
