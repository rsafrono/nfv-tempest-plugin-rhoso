from kubernetes import client, config
from openshift.dynamic import DynamicClient
from kubernetes.stream import stream
from kubernetes.client.rest import ApiException
import re

class openshift_client:
    def __init__(self):
      config.load_incluster_config()
      self.k8s_core_v1_api = client.CoreV1Api()
      self.dynamic_client = DynamicClient(client.ApiClient())

    def read_secret_data(self, secret_name, namespace):
        """
        returns a dictionary of secret data in b64
        """
        v1_secret = self.dynamic_client.resources.get(api_version='v1', kind='Secret')
        return v1_secret.get(namespace=namespace, name=secret_name).data

    def execute_command_in_pod(self, name, namespace, container, command):
        exec_command = ["/bin/sh", "-c", command]

        resp = stream(self.k8s_core_v1_api.connect_get_namespaced_pod_exec,
                    name,
                    namespace,
                    command=exec_command,
                    stderr=True, stdin=False,
                    stdout=True, tty=False,
                    _preload_content=False,
                    container=container)

        while resp.is_open():
            resp.update(timeout=1)
            if resp.peek_stdout():
                stdout = resp.read_stdout()
            if resp.peek_stderr():
                stderr = resp.read_stderr()

        resp.close()

        if resp.returncode != 0:
            raise Exception(stderr)

        return stdout

    def search_pods_using_regex(self, regex, namespace):
        pod_list = []
        pattern = re.compile(regex)
        v1_pods = self.dynamic_client.resources.get(api_version='v1', kind='Pod')
        all_pods = v1_pods.get(namespace=namespace).to_dict()['items']
        for pod in all_pods:
            if pattern.match(pod['metadata']['name']):
                pod_list.append(pod)
        return pod_list

    def delete_pod(self, name, namespace):
        try:
            api_response = self.k8s_core_v1_api.delete_namespaced_pod(name, namespace)
            return api_response
        except ApiException as e:
            raise ApiException(f'Unable to delete pod {name} in namespace {namespace}')
