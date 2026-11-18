# Architecture Decision Records

An ADR (Architecture Decision Record) is a short note explaining one decision that shapes this
repository's code, so the reason lives in the repository instead of only in heads or pull request
threads. Write one when a change makes such a decision: copy `template.md` to the next free number
and add it to the table below in the same pull request. Never edit the decision of an accepted ADR;
supersede it with a new one and mark the old one `Superseded by NNNN`.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-capture-with-platform-tools.md) | Capture with the platform's packet tools | Accepted |
| [0002](0002-run-zeek-on-the-sensor.md) | Run Zeek on the sensor; packets never leave the host | Accepted |
| [0003](0003-typed-records-upload-contract.md) | Upload typed records over a contract owned by Enigma-Publisher | Accepted |
| [0004](0004-retry-then-buffer-uploads-on-disk.md) | Retry, then buffer failed uploads on disk | Accepted |
| [0005](0005-subnet-exclusion-fails-closed.md) | Subnet exclusion fails closed | Accepted |
