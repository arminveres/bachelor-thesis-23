"""
This modules holds the logic for Controller Nodes
"""
import asyncio
import importlib
import json
import sys
import os
import time

from agents.agent_container import (  # noqa:E402
    AgentContainer,
    AriesAgent,
    arg_parser,
    create_agent_with_args,
)
from support.agent import DEFAULT_EXTERNAL_HOST
from support.utils import log_msg, prompt, prompt_loop, log_json, LogLevel
from support.perf_analysis import log_time_to_file

# Our custom software to be updated
import shady_stuff


class NodeAgent(AriesAgent):
    """
    A NodeAgent represents an end target, that will hold credentials.
    TODO: Further differentiate between controller, function, edge nodes.
    """

    def __init__(
        self, ident: str, http_port: int, admin_port: int, log_level=LogLevel.DEBUG, **kwargs
    ):
        super().__init__(
            ident=ident,
            http_port=http_port,
            admin_port=admin_port,
            log_level=LogLevel.DEBUG,
            **kwargs,
        )
        self.connection_id = None
        self._connection_ready = None
        # NOTE: (aver) We assume only one credential for the moment
        self.cred_id = None

    # =============================================================================================
    # Webhook handler implementations
    # =============================================================================================
    async def handle_invitation(self, message):
        """
        Handle invitation received for connections
        """
        if self.log_level == LogLevel.DEBUG:
            self.log("Received invitation:", message["content"])
            self.log("\n\ngot\n\n", message)

    async def handle_revocation_notification(self, message):
        """
        Handles incoming revocation, perpetrated by the auditor and issued by Issuer
        """

        log_time_to_file(
            "revocation", f"REV_RECEIVED: time: {time.perf_counter_ns()}, node: {self.ident}\n"
        )

        if self.log_level == LogLevel.DEBUG:
            self.log("Received revocation notification message:")
            self.log_json(message)
        message["comment"] = json.loads(message["comment"])
        diff = await self.get_update(message)
        await self.notify_admin_of_update(diff)

    # =============================================================================================
    # Additional methods
    # =============================================================================================
    async def get_update(self, vulnerabilities):
        """
        Demonstrative method to provide update to node.
        """
        UPDATER_URL = os.getenv("UPDATER_URL") or f"http://{DEFAULT_EXTERNAL_HOST}:8080/"
        async with self.client_session.get(UPDATER_URL) as resp:
            # we are overwriting the existing file as update
            with open("shady_stuff.py", "wb") as fd:
                while True:
                    chunk = await resp.content.read(1024)
                    if not chunk:
                        break
                    fd.write(chunk)
            old = shady_stuff.version()
            self.log("Old version")
            self.log(old)
            self.log("Received new update:")
            importlib.reload(shady_stuff)
            new = shady_stuff.version()
            self.log(new)
            if not old["version"] < new["version"]:
                raise Exception("shutdown, wrong update delivered.")
            diff = {
                "old": {"components": {"software": {"shady_stuff": old["version"]}}},
                "new": {"components": {"software": {"shady_stuff": new["version"]}}},
            }
            return diff

    async def notify_admin_of_update(self, changes):
        # TODO: (aver) possibly create a connection
        cred = await self.admin_GET(f"/credential/{self.cred_id}")
        idx = cred["schema_id"].find(":")
        if idx == -1:
            raise Exception
        did = cred["schema_id"][:idx]
        response = await self.admin_GET(f"/resolver/resolve/did:sov:{did}")
        # if not response.ok:
        #     raise Exception
        issuer_url = response["did_document"]["service"][0]["serviceEndpoint"]
        issuer_url = issuer_url[:-1] + "2"

        payload = {"node_did": self.did, "diff": changes}
        response = await self.client_session.post(
            url=f"{issuer_url}/webhooks/topic/node_updated/",
            json=payload,
        )
        if not response.ok:
            log_msg(response)
            return
        if self.log_level == LogLevel.DEBUG:
            log_msg(response)
        # response = await response.json()
        # log_json(response)

    async def get_credential_state(self):
        """
        Prints and returns the current credential state (true if revoked, or false for valid)
        """
        if self.cred_id is None:
            response = await self.admin_GET("/credentials")
            res = response["results"]
            if len(res) == 0:
                self.log("No existing credential.")
                return
            self.cred_id = res[-1]["referent"]

        self.log("The following credential:")
        response = await self.admin_GET(f"/credential/{self.cred_id}")
        log_json(response)
        self.log("Status:")
        response = await self.admin_GET(f"/credential/revoked/{self.cred_id}")
        log_json(response)
        return response["revoked"]


async def register_subnode(agent_container: AgentContainer, node_name: str):
    """
    Registers a subnode with name `node_name` to the agent in the `agent_container`
    TODO: (aver) could move this to AgentContainer implementation
    """
    await agent_container.agent.register_or_switch_wallet(
        target_wallet_name=f"{agent_container.ident}.sub.{node_name}",
        public_did=agent_container.public_did
        and (
            (not agent_container.endorser_role) or (not agent_container.endorser_role == "author")
        ),
        webhook_port=None,
        mediator_agent=agent_container.mediator_agent,
        endorser_agent=agent_container.endorser_agent,
        taa_accept=agent_container.taa_accept,
    )


async def create_node_agent(args):
    # First setup all the agent related stuff
    agent_container = await create_agent_with_args(args)
    agent_container.prefix = agent_container.ident

    cache_path = f".agent_cache/{agent_container.ident}"
    provision = False
    if os.path.exists(cache_path):
        provision = True
        with open(cache_path, mode="r", encoding="utf-8") as cache:
            agent_container.seed = cache.read()

    _agent = NodeAgent(
        # "node.agent",
        agent_container.ident,
        agent_container.start_port,
        agent_container.start_port + 1,
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
    )

    if not provision:
        with open(cache_path, "wb") as cache:
            cache.write(bytes(_agent.seed, "utf-8"))
    await agent_container.initialize(the_agent=_agent)
    with open(".agent_cache/mass_onboarding", "ab") as cache:
        output = f"name: {agent_container.ident}\ndid: {agent_container.agent.did}\n"
        cache.write(bytes(output, "utf-8"))
    return agent_container


async def main():
    parser = arg_parser()
    args = parser.parse_args()
    agent_container = await create_node_agent(args)

    def add_option(options: dict, key: str, value: str) -> dict:
        """Adds an option to the dict and returns a sorted version"""
        options[key] = value
        options = dict(sorted(options.items(), key=lambda x: x[1]))
        return options

    prompt_options = {
        "cred_status": "  [1]: Credential Status\n",
        "exit": "  [x]: Exit\n",
    }
    if agent_container.multitenant:
        prompt_options = add_option(
            prompt_options, "reg_subnode", "  [2]: Register a subnode, i.e., and edge node\n"
        )

    def get_prompt():
        """
        Builds the prompt out of the options dictionary
        """
        # prompt_options.update()
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

        # try to do an interactive loop
        # Setup options and make them dicts, so that they can be changed at runtime, although
        # watch out for duplicated keys.
        async for option in prompt_loop(get_prompt):
            if option is not None:
                option.strip()
            if option is None or option == "":
                log_msg("Please give an option")

            if option == "1":
                await agent_container.agent.get_credential_state()

            elif option == "2" and agent_container.multitenant:
                edge_node_name = (await prompt("Enter a name for the subnode: ")).strip()
                await register_subnode(agent_container, edge_node_name)

            elif option in "xX":
                return

            else:
                log_msg("Unknown option: " + option)

    # WARN: (aver) We discovered that running in non-interactive mode creates an exception
    # because of the prompt toolkit. We therefore expect it and assume it is because of
    # non-interactiveness
    except PermissionError:
        while True:
            await asyncio.sleep(1)

    finally:
        await agent_container.terminate()


if __name__ == "__main__":
    # execute main
    try:
        asyncio.get_event_loop().run_until_complete(main())
    except KeyboardInterrupt:
        sys.exit(1)
