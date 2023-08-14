from .security import Security
import os
import time
import subprocess

class KerberosError(Exception):
    pass

NEED_KRB181_WORKAROUND = None  # type: Optional[bool]

class KerberosSecurity(Security):
    def __init__(self):
        self.principal = os.getenv("EG_KERBEROS_PRINCIPAL")
        self.keytab = os.getenv("EG_KERBEROS_KEYTAB")
        self.reinit_frequency = os.getenv("EG_KERBEROS_REINIT_FREQUENCY", 60)
        self.ccache = os.getenv("KRB5CCNAME", f"/tmp/krb5cc_{os.getuid()}")

    def start(self):
        if not self.keytab or not self.principal:
            raise ValueError("Keytab renewer not starting, keytab and principal must be configured")

        while True:
            self.renew()
            time.sleep(self.reinit_frequency)

    def renew(self):
        cmdv = [
            "kinit",
            "-r", self.reinit_frequency,
            "-k",  # host ticket
            "-t", self.keytab,  # specify keytab
            "-c", self.ccache,  # specify credentials cache
            self.principal
        ]

        subp = subprocess.Popen(cmdv,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                            close_fds=True,
                            bufsize=-1,
                            universal_newlines=True)

        subp.wait()
        if subp.returncode != 0:
            self.log.error(
                "Couldn't reinit from keytab! `kinit' exited with %s.\n%s\n%s",
                subp.returncode, "\n".join(subp.stdout.readlines()), "\n".join(subp.stderr.readlines())
            )
            return

        global NEED_KRB181_WORKAROUND  # pylint: disable=global-statement
        if NEED_KRB181_WORKAROUND is None:
            NEED_KRB181_WORKAROUND = self.detect_conf_var()
        if NEED_KRB181_WORKAROUND:
            # (From: HUE-640). Kerberos clock have seconds level granularity. Make sure we
            # renew the ticket after the initial valid time.
            time.sleep(1.5)
            self.perform_krb181_workaround(self.principal)

    def perform_krb181_workaround(self, principal: str):
      """
      Workaround for Kerberos 1.8.1.

      :param principal: principal name
      :return: None
      """
      cmdv = ["kinit",
              "-c", self.ccache,
              "-R"]  # Renew ticket_cache

      self.log.info(
          "Renewing kerberos ticket to work around kerberos 1.8.1: %s", " ".join(cmdv)
      )

      ret = subprocess.call(cmdv, close_fds=True)

      if ret != 0:
          self.log.error(
              "Couldn't renew kerberos ticket in order to work around Kerberos 1.8.1 issue. Please check that "
              f"the ticket for '{self.principal}' is still renewable:\n  $ kinit -f -c {self.ccache}\nIf the 'renew until' date is the "
              "same as the 'valid starting' date, the ticket cannot be renewed. Please check your KDC "
              "configuration, and the ticket renewal policy (maxrenewlife) for the '{self.principal}' and `krbtgt' "
              "principals."
          )
          return

    def detect_conf_var(self) -> bool:
        """Return true if the ticket cache contains "conf" information as is found
        in ticket caches of Kerberos 1.8.1 or later. This is incompatible with the
        Sun Java Krb5LoginModule in Java6, so we need to take an action to work
        around it.
        """
        with open(self.ccache, 'rb') as file:
            # Note: this file is binary, so we check against a bytearray.
            return b'X-CACHECONF:' in file.read()
