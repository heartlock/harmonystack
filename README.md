# harmonystack
 middle layer between harmonycloud and opendaylight

# OpenDaylight Network Provider for Kubernetes

HarmonyStack is an sdn network provider for kubernetes. HarmonyStack is devided into two functions:

* HarmonyStack running on the same host with kube-controller-manager, which provides network management by sdn
* HarmonyStack running on each minion host, which setups container's network interfaces

## How to run it

Notes: You need a working OpenDaylight and Kubernetes before deploying HarmonyStack.


```
mkdir -p $GOPATH/src/github.com/heartlock/
cd $GOPATH/src/github.com/heartlock/
git clone https://github.com/heartlock/harmonystack.git
cd harmonystack
make && make install
```

Configure OpenDaylight authorization properties in `/etc/harmonystack.conf`:

```
[Global]
auth-url = http://192.168.33.33:5000/v2.0
username = admin
password = admin
tenant-name = admin
region = RegionOne
ext-net-id = <Your-external-network-id>

[LoadBalancer]
create-monitor = yes
monitor-delay = 1m
monitor-timeout = 30s
monitor-max-retries = 3

[Plugin]
plugin-name = ovs
```

Start:

```
# Start harmonystack on each machine
harmonystack -logtostderr=true -v=4 -port=:4237
```

Configure kubernetes `controller-manager` and `kubelet` using opendaylight network provider:

```
kube-controller-manager --network-provider=127.0.0.1:4237 --...
kubelet --network-provider=127.0.0.1:4237 --....
```