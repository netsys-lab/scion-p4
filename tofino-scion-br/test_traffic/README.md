# Functionality test files

The pcap files contained in this folder were recorded on both sides of a SCION reference implementation border router and can be used to check whether the Tofino implementation works as expected. **All recorded connections are unidirectional.**

To allow different scenarios, every test case was recorded in each diretion, where AS 1 is the core AS the border router which is tested belongs to. AS6 is a non-core AS directly connected to the tested border router, while AS 2 is a non-core AS that is connected to another border router inside AS 1.

## To perform a test

Set up the Tofino using the usual commands. Run

```
$ python3 ${controller}/load_config.py ${CONFIG}/switch_config.json
```
with the switch_config.json inside [config](config/) (the difference between hardware and sim are the port IDs which are already matced to the Tofino 2 ports inside the testbed). The BFD script should not run during testcases to avoid disruptions due to BFD frames, but to set up all paths inside the Tofino it has to be run once at the beginning:
```
$ sudo -E ${controller}/bfd_handling.py -k ${SCION}/gen/ASff00_0_1/keys/master0.key -b ${CONFIG}/bfd_config.json -t
```
where the `-t` signals the testmode which only sets up all interface once and then exits to not further block the Tofino's grpc interface.

The [key file](master0.key) needed to allow hop field validation for the included pcap files is included in this folder. 

On the side of the Tofino where the receiving AS would have been connected, run the test script with
```
$ sudo -E python3 ${controller}/test.py -f <receiver_file.pcap>
```
On the Tofino port where the sending AS would have been connected replay the corresponding `<sender_file.pacp>`.
