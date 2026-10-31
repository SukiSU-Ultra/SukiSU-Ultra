package com.sukisu.ultra.ai

import com.sukisu.ultra.ai.api.AiEnvironmentScopes

/** Copy only the capability switches the host needs for an environment probe. */
internal fun AiConfig.toEnvironmentScopes(): AiEnvironmentScopes = AiEnvironmentScopes(
    root = allowRootAccess,
    superuser = allowSuperuserAccess,
    superuserRootControl = allowSuperuserRootControl,
    superuserTemporaryRoot = allowSuperuserTemporaryRoot,
    superuserSwitch = allowSuperuserSwitch,
    modules = allowModuleAccess,
    extensions = allowExtensionAccess,
    web = allowWebAccess,
    theme = allowThemeRead,
    includeContext = includeContext,
)
