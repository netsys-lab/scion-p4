# SPDX-License-Identifier: AGPL-3.0-or-later

#This script sets up the test infrastructure completely, and opens tabs for all seperate scripts etc.
#This is a lot easier if sudo is setup to work without passwords in the sudoers file for the user running the script.


export WS=~/workspace
export ICA_TOOLS=$WS/bf-sde-9.13.0/tools
export SCION=~/scion
export BR=$WS/p4-scion-br
export CONFIG=$WS/p4-scion-br/test_infrastructure/config
export SDE=$WS/bf-sde-9.13.0

cd $BR/test_infrastructure
./demo stop
./demo build
./demo run

cd $SDE
source $ICA_TOOLS/set_sde.bash

#$ICA_TOOLS/p4_build.sh --with-tofino2 $BR/p4src/scion.p4

cd $SDE
sudo ./tools/veth_setup.sh

gnome-terminal --tab --title 'model' --working-directory="$SDE" -- bash -c "source tools/set_sde.bash;./run_tofino_model.sh --arch tofino2 -p scion -f $CONFIG/ports2.json; exec bash"

gnome-terminal --tab --title 'switchd' --working-directory="$SDE" -- bash -c "source tools/set_sde.bash;./run_switchd.sh --arch tofino2 -p scion; exec bash"

read

cd $BR
python3 controller/load_config.py $CONFIG/switch_config2.json

read

gnome-terminal --tab --title 'bfd' --working-directory="$BR" -- bash -c "sudo -E python3 controller/bfd_handling.py --grpc_address 127.0.0.1:50052 -k $SCION/gen/ASff00_0_1/keys/master0.key -b $CONFIG/bfd_config2.json -i veth5; bash"

