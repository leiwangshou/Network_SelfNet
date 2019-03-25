#! /bin/bash

tmux new-session -d -s abc
tmux new-window -n abc1 './project /projects/project3/infiles/1.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc2 './project /projects/project3/infiles/2.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc3 './project /projects/project3/infiles/3.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc4 './project /projects/project3/infiles/4.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc5 './project /projects/project3/infiles/5.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc6 './project /projects/project3/infiles/6.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc7 './project /projects/project3/infiles/7.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc8 './project /projects/project3/infiles/8.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc9 './project /projects/project3/infiles/9.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc10 './project /projects/project3/infiles/10.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc11 './project /projects/project3/infiles/11.txt /projects/project3/infiles/Project2Topo.pcap'
tmux new-window -n abc12 './project /projects/project3/infiles/12.txt /projects/project3/infiles/Project2Topo.pcap'
tmux attach-session -d -t abc

