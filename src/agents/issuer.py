import asyncio
import json
import sys
from datetime import date
import time

from agents.agent_container import (
    CRED_PREVIEW_TYPE,
    AgentContainer,
    AriesAgent,
    arg_parser,
    create_agent_with_args,
)
from support.agent import DEFAULT_INTERNAL_HOST
from support.database import OrionDB
from support.utils import log_json, log_msg, log_status, prompt, prompt_loop, LogLevel
from support.perf_analysis import log_time_to_file

DB_NAME = "db1"


class IssuerAgent(AriesAgent):
    """
    This agent will be a credential issuer from the maintainer/manufacturer point of view.
    It also works as a database administrator, being able to create new users and keys, with
    complete control over Access Control
    """

    def __init__(
        self,
        ident: str,
        http_port: int,
        admin_port: int,
        orion_db_url=f"http://{DEFAULT_INTERNAL_HOST}:6001",
        log_level=LogLevel.DEBUG,
        **kwargs,
    ):
        super().__init__(
            ident=ident, http_port=http_port, admin_port=admin_port, log_level=log_level, **kwargs
        )

        self.log_level = log_level

        # TODO: (aver) find a better way to manage keys
        self.db_username = "admin"  # ident

        self.db_client = OrionDB(
            orion_db_url=orion_db_url,
            username=self.db_username,
            client_session=self.client_session,
            log_level=self.log_level,
        )

        # TODO: (aver) remove hardcoded self.connection_id
        self.connection_id = None
        self._connection_ready = None
        # TODO define a dict to hold credential attributes based on cred_def_id
        self.cred_state = {}
        self.cred_attrs = {}
        self.cred_def_id = None

    # =============================================================================================
    # Properties, getters and setters
    # =============================================================================================
    @property
    def connection_ready(self):
        return self._connection_ready.done() and self._connection_ready.result()

    def reset_connection(self):
        """
        Temporary function to reset connections in order to allow for multiple connections to be
        made.
        """
        self._connection_ready = None
        self.connection_id = None

    # =============================================================================================
    # Webhook handler implementations
    # =============================================================================================
    async def handle_connections(self, message):
        conn_id = message["connection_id"]

        if (not self.connection_id) and message["rfc23_state"] == "invitation-sent":
            print(self.ident, "set connection id", conn_id)
            self.connection_id = conn_id

        if (
            message["connection_id"] == self.connection_id
            and message["rfc23_state"] == "completed"
            and (self._connection_ready and not self._connection_ready.done())
        ):
            self.log("Connected")
            self._connection_ready.set_result(True)

    async def handle_out_of_band(self, message):
        print("handle_out_of_band()")
        log_json(message)

    async def handle_issue_credential_v2_0(self, message):
        state = message["state"]
        cred_ex_id = message["cred_ex_id"]
        prev_state = self.cred_state.get(cred_ex_id)

        if prev_state == state:
            return  # ignore

        node_name = [
            i["value"]
            for i in message["cred_preview"]["attributes"]
            if i["name"] == "controller_id"
        ][0]

        response = await self.db_client.query_key(DB_NAME, node_name)

        if response is None:
            print("\n\n\tsomething massively went wrong, if an existing db key is none!")
            sys.exit(1)

        # update credentials
        response["cred_ex_id"] = cred_ex_id
        response["valid"] = True
        await self.db_client.record_key(DB_NAME, node_name, response)

        self.cred_state[cred_ex_id] = state
        self.log(f"Credential: state = {state}, cred_ex_id = {cred_ex_id}")

        if state == "request-received":
            # TODO issue credentials based on offer preview in cred ex record
            if not message.get("auto_issue"):
                await self.admin_POST(
                    f"/issue-credential-2.0/records/{cred_ex_id}/issue",
                    {"comment": f"Issuing credential, exchange {cred_ex_id}"},
                )

    async def handle_notify_vulnerability(self, message):
        """
        Handle vulnerabilities presented to the maintainer/admin/issuer
        """
        # FIXME: (aver) improve this 4 times nested loop !!!!
        if self.log_level == LogLevel.INFO or self.log_level == LogLevel.DEBUG:
            log_msg("Received vulnearbility:")
            log_json(message)
        # Go through each vulnerability
        for vuln_notif in message:
            vuln_db_name = vuln_notif["db_name"]
            vulnerability = vuln_notif["vulnerability"]

            # mark devices to be revoked
            for device in self.db_client.db_keys[vuln_db_name]:
                db_result = await self.db_client.query_key(vuln_db_name, device)
                if self.log_level == LogLevel.DEBUG:
                    log_json(db_result)
                    log_json(vulnerability)

                for component_key, component_value in db_result["components"].items():
                    for (
                        vuln_component_key,
                        vuln_component_value,
                    ) in vulnerability.items():
                        if component_key != vuln_component_key:
                            continue
                        # find vulnerability that matches the marked one
                        if vuln_component_value.items() <= component_value.items():
                            self.log(
                                f"Found existing vulnerability for device {device} with component {vuln_component_value}"
                            )
                            reason = {
                                "reason": "vulnerability",
                                "component": {vuln_component_key: vuln_component_value},
                            }
                            await self.revoke_credential(
                                db_result["cred_ex_id"],
                                vuln_db_name,
                                device,
                                reason,
                            )

    async def handle_node_updated(self, message):
        """
        Handle when a node sends an notification about its update state
        """
        node_did = "did:sov:" + message["node_did"]
        if self.log_level == LogLevel.INFO or self.log_level == LogLevel.DEBUG:
            self.log(f"Node {node_did} was updated")
            log_json(message)
        # node_did = message["node_did"]

        for key, value in self.db_client.db_keys[DB_NAME].items():
            # if the did value is missing get it!
            if value.get("controller_did") is None:
                _ = await self.db_client.query_key(DB_NAME, key)

            if value.get("controller_did") == node_did:
                node_name = key
                self.log(f"Found node: {node_name}")
                break

        # TODO: (aver) make components and node_cred pluggable
        components = {
            "software": {"python3": 3.9, "indy": 1.16, "shady_stuff": 0.2},
            "firmware": {},
            "hardware": {"raspberry-pi": "4B"},
        }
        node_cred = {
            "controller_id": node_name,
            "date": date.isoformat(date.today()),
            "components": str(components),
            "security_level": "low",
        }

        db_entry = node_cred.copy()
        db_entry["controller_did"] = node_did
        db_entry["components"] = components
        db_entry["valid"] = False

        await self.db_client.record_key(DB_NAME, node_name, db_entry)
        await self.issue_credential(node_did, node_name, node_cred, DB_NAME)
        log_time_to_file("update", f"UPDATE: time: {time.time_ns()}, node: {node_name}\n")

    # =============================================================================================
    # Additional methods
    # =============================================================================================
    async def revoke_credential(
        self,
        cred_ex_id: str,
        db_name: str,
        node_name: str,
        revocation_reason: dict,
    ):
        """
        Revoke a credentials and publish it.
        """
        response = await self.db_client.query_key(db_name, node_name)
        cred_ex_id = response.get("cred_ex_id")

        # update database with removed credential id
        response["cred_ex_id"] = ""
        response["valid"] = False
        await self.db_client.record_key(db_name, node_name, response)

        # FIXME: (aver) remove hard coded connection_id and retrieve or store in database
        # TODO: (aver) fix for offline devices
        await self.admin_POST(
            "/revocation/revoke",
            {
                "cred_ex_id": cred_ex_id,
                "publish": True,
                "connection_id": self.db_client.db_keys[db_name][node_name]["connection_id"],
                "comment": json.dumps(revocation_reason),
            },
        )
        log_time_to_file(
            "revocation", f"REVOCATION: time: {time.time_ns()}, node: {node_name}\n"
        )

    async def issue_credential(
        self,
        node_did: str,
        node_name: str,
        node_cred: dict,
        db_name: str,
    ):
        """
        Issue a predetermined credential to a node
        params:
            node_did: public did of the targeted node
            node_name: name and identifier of targeted node
            node_cred: credential to be issued
            domain: databse name where it will be stored
        """
        recipient_key = await self.send_invitation(node_did)
        # we set the recipient key for later identification
        self.db_client.db_keys[db_name][node_name]["recipient_key"] = recipient_key

        self._connection_ready = asyncio.Future()
        if self.log_level == LogLevel.DEBUG:
            log_msg("Waiting for connection...")
        await self.detect_connection()

        # Set the connection id for each controller
        response = await self.admin_GET("/connections")
        if self.log_level == LogLevel.DEBUG:
            log_json(response)

        # TODO: (aver) remove hardcoded key_name and add logic for general key check
        # also remove hardcoded connection_id
        for conn in response["results"]:
            if conn["invitation_key"] == recipient_key:
                conn_id = conn["connection_id"]
                self.db_client.db_keys[db_name][node_name]["connection_id"] = conn_id
                # remove recipient/invitation key
                self.db_client.db_keys[db_name][node_name].pop("recipient_key")

        self.reset_connection()

        if self.log_level == LogLevel.INFO or LogLevel.DEBUG:
            log_status(f"# Issuing credential offer to {node_name}")
        self.cred_attrs[self.cred_def_id] = node_cred
        cred_preview = {
            "@type": CRED_PREVIEW_TYPE,
            "attributes": [
                {"name": n, "value": v} for (n, v) in self.cred_attrs[self.cred_def_id].items()
            ],
        }
        offer_request = {
            "connection_id": conn_id,
            "comment": f"Offer on cred def id {self.cred_def_id}",
            "credential_preview": cred_preview,
            "filter": {"indy": {"cred_def_id": self.cred_def_id}},
        }
        _ = await self.admin_POST("/issue-credential-2.0/send-offer", offer_request)
        log_time_to_file("issue", f"ISSUING: time: {time.time_ns()}, node: {node_name}\n")

    async def onboard_node(self, db_name: str, node_name: str, node_did: str):
        """
        params:
            agent_container: AgentContainer,
            domain: str, database name, which also works as domain name
            node_name: str,
            node_did: str
        """
        # Currently the credential is of the same format as the entry to the database
        components = {
            "software": {"python3": 3.9, "indy": 1.16, "shady_stuff": 0.1},
            "firmware": {},
            "hardware": {"raspberry-pi": "4B"},
        }
        node_cred = {
            "controller_id": node_name,
            "date": date.isoformat(date.today()),
            "components": str(components),
            "security_level": "low",
        }

        # WARN: (aver) the did has to be amended with the method for the resolver to work
        node_did = "did:sov:" + node_did

        # we extend the credential with components so that the auditor can register them
        # NOTE: (aver) In an improved scenario, the config would be read in, instead of artificially
        # created
        db_entry = node_cred.copy()
        db_entry["controller_did"] = node_did
        db_entry["components"] = components

        await self.db_client.record_key(db_name, node_name, db_entry)
        await self.issue_credential(node_did, node_name, node_cred, db_name)

    async def mass_onboard(self):
        """
        Rudimentally onboards a list of devices
        """
        devices = []
        device = {}
        with open(".agent_cache/mass_onboarding", mode="r", encoding="utf-8") as file:
            for line in file:
                key, value = line.strip().split(": ")
                device[key] = value
                if key == "did":
                    devices.append(device)
                    device = {}
        for node in devices:
            await self.onboard_node(DB_NAME, node["name"], node["did"])

    async def remove_device(self, node_name: str):
        # db_result = await self.db_client.query_key(DB_NAME, node_name)
        await self.revoke_credential(
            "",
            DB_NAME,
            node_name,
            {"reason": "manually revoked by maintainer"},
        )
        _ = await self.db_client.delete_key(DB_NAME, node_name)
        self.log(f"Successfully removed node: {node_name}")


# =================================================================================================
# Helper functions
# =================================================================================================
async def create_agent_container(args) -> AgentContainer:
    # First setup all the agent related stuff
    agent_container = await create_agent_with_args(args)
    agent_container.seed = "Autho_00000000000000000000000000"
    agent_container.prefix = agent_container.ident

    agent = IssuerAgent(
        ident=agent_container.ident,
        http_port=agent_container.start_port,
        admin_port=agent_container.start_port + 1,
        genesis_data=agent_container.genesis_txns,
        genesis_txn_list=agent_container.genesis_txn_list,
        no_auto=agent_container.no_auto,
        tails_server_base_url=agent_container.tails_server_base_url,
        revocation=agent_container.revocation,
        timing=agent_container.show_timing,
        multitenant=agent_container.multitenant,
        mediation=agent_container.mediation,
        wallet_name=agent_container.ident,
        # WARN: (aver) key is same as identity, which is insecure, watch out!
        # this could be stored in Secure Element (SE)
        wallet_key=agent_container.ident,
        wallet_type=agent_container.wallet_type,
        aip=agent_container.aip,
        endorser_role=agent_container.endorser_role,
        seed=agent_container.seed,
        prefix=agent_container.prefix,
        log_level=args.log_level,
    )
    await agent_container.initialize(
        the_agent=agent,
    )
    return agent_container


async def checked_schema_cred_creation(
    agent_container: AgentContainer, schema_name, schema_attributes, schema_version
):
    try:
        # The whole demo code is so nested, I don't really see the possiblity for simplifying or
        # catching the correct error
        agent_container.cred_def_id = await agent_container.create_schema_and_cred_def(
            schema_name, schema_attributes, schema_version
        )
    except Exception as e:
        # We check whether the exception is about the schema existing
        resp = str(e).find("exists")
        # if the exception was about something else, then we raise it againt
        if resp == -1:
            raise e
        # we need another way to get cred_def_id
        response = await agent_container.admin_GET(
            # "/credential-definitions/created/?issuer_did=did:sov:8BJ4EjbZM87wCasqjE1kt"
            "/credential-definitions/created"
        )
        log_json(response)
        agent_container.cred_def_id = response["credential_definition_ids"][0]
    # We add the schema definition id for later possiblity or reissuing, could be handled better...
    agent_container.agent.cred_def_id = agent_container.cred_def_id


async def setup_database(agent_container: AgentContainer, db_name: str):
    """
    Setup the database, and register schema and credential on database
    """
    await agent_container.agent.db_client.create_database(db_name)

    schema_name = "controller id schema"
    schema_attributes = ["controller_id", "date", "components", "security_level"]
    schema_version = "0.0.1"

    await checked_schema_cred_creation(
        agent_container, schema_name, schema_attributes, schema_version
    )
    log_msg(
        f"Setup database: '{db_name}' and schema '{schema_name}', '{schema_attributes}', {schema_version}"
    )
    # we create an auditor user, who then will mark software as vulnerable
    await agent_container.agent.db_client.create_user("auditor")
    log_status("Created auditor account")


# =================================================================================================
# MAIN Function
# =================================================================================================
async def main():
    parser = arg_parser()
    args = parser.parse_args()
    agent_container = await create_agent_container(args)

    def add_option(options: dict, key: str, value: str) -> dict:
        """Adds an option to the dict and returns a sorted version"""
        options[key] = value
        options = dict(sorted(options.items(), key=lambda x: x[1]))
        return options

    # Setup options and make them dicts, so that they can be changed at runtime
    prompt_options = {
        "setup_db": "  [1]: Setup/Load existing Database, Schema and Credential\n",
        "rm_node": "  [2]: Remove an onboarded node from the infrastructure\n",
        "exit": "  [x]: Exit\n",
        "help": "  [h]: Print help\n",
    }

    def get_prompt():
        """
        Builds the prompt out of the options dictionary
        """
        prompt_options.update()
        options_str = "Options:\n"
        for option in list(prompt_options.items()):
            options_str += option[1]
        options_str += "> "
        return options_str

    try:
        # =========================================================================================
        # Event Loop
        # =========================================================================================
        # New prompt based event loop, events such as webhooks still run in the background.

        await setup_database(agent_container, DB_NAME)
        prompt_options.pop("setup_db")
        # add onboarding option and update order by values
        prompt_options = add_option(
            prompt_options, "onboard", "  [3]: Onboard node with public DID\n"
        )
        prompt_options = add_option(prompt_options, "mass_onboard", "  [4]: Mass Onboard fleet\n")
        prompt_options = add_option(
            prompt_options, "db_qall", "  [5]: Query all nodes from Database\n"
        )
        prompt_options = add_option(
            prompt_options, "db_qsingle", "  [6]: Query single node from Database\n"
        )

        async for option in prompt_loop(get_prompt):
            if option is not None:
                option = option.strip()
            if option is None or option == "":
                log_msg("Please give an option")

            # run options
            # if option == "1":
            #     if not prompt_options.get("setup_db"):
            #         log_msg(f"invalid option, {option}")
            #         continue

            #     await setup_database(agent_container, DB_NAME)
            #     prompt_options.pop("setup_db")
            #     # add onboarding option and update order by values
            #     prompt_options = add_option(
            #         prompt_options, "onboard", "  [3]: Onboard node with public DID\n"
            #     )
            #     prompt_options = add_option(
            #         prompt_options, "mass_onboard", "  [4]: Onboard fleet with public DID\n"
            #     )

            if option == "2":
                node_name = await prompt("Enter Node Name: ")
                if node_name is None or node_name == "":
                    log_msg("Aborting Node onboarding...")
                    continue
                node_name = node_name.strip()
                await agent_container.agent.remove_device(node_name)

            elif option == "3":
                if not prompt_options.get("onboard"):
                    log_msg(f"invalid option, {option}")
                    continue

                node_name = await prompt("Enter Node Name: ")
                if node_name is None or node_name == "":
                    log_msg("Aborting Node onboarding...")
                    continue
                node_did = await prompt("Enter Node DID: ")
                if node_did is None or node_did == "":
                    log_msg("Aborting Node onboarding...")
                    continue
                node_name = node_name.strip()
                node_did = node_did.strip()

                await agent_container.agent.onboard_node(
                    db_name=DB_NAME,
                    node_did=node_did,
                    node_name=node_name,
                )

            elif option == "4":
                await agent_container.agent.mass_onboard()

            elif option == "5":
                log_json(
                    [
                        await agent_container.agent.db_client.query_key(DB_NAME, device)
                        for device in agent_container.agent.db_client.db_keys[DB_NAME]
                    ]
                )

            elif option == "6":
                if node_name is None or node_name == "":
                    log_msg("Aborting search...")
                    continue
                log_json(
                    await agent_container.agent.db_client.query_key(DB_NAME, node_name.strip())
                )

            elif option == "h":
                print(
                    """
You can exit via Ctrl-c, or inputting x.
You can exit the current prompot by Ctrl-d or submit the current input by hitting enter.
                """
                )
            elif option == "x":  # shut off gracefully
                sys.exit(0)

    finally:  # Shut down the agent gracefully
        await agent_container.terminate()


if __name__ == "__main__":
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(main())
    except KeyboardInterrupt:
        sys.exit(1)
