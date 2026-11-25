package de.mahlkoenig.e64local

import android.app.Application
import android.content.Context
import de.mahlkoenig.e64local.crypto.AssetModuleProvider
import de.mahlkoenig.e64local.crypto.KeystoreCipher
import de.mahlkoenig.e64local.setup.ModuleProvider
import de.mahlkoenig.e64local.setup.SetupCoordinator
import de.mahlkoenig.e64local.storage.TokenStore

/**
 * The app's only object graph. Everything is constructed here explicitly so
 * there is no service locator that could be replaced by a remote one.
 */
class App : Application() {

    lateinit var tokenStore: TokenStore
        private set

    lateinit var moduleProvider: ModuleProvider
        private set

    lateinit var runnerProvider: ModuleProvider
        private set

    lateinit var setupCoordinator: SetupCoordinator
        private set

    override fun onCreate() {
        super.onCreate()
        tokenStore = TokenStore(
            getSharedPreferences(TokenStore.PREFS, Context.MODE_PRIVATE),
            KeystoreCipher(),
        )
        moduleProvider = AssetModuleProvider(this)
        runnerProvider = AssetModuleProvider(this, "e64local_action_run.php")
        setupCoordinator = SetupCoordinator(tokenStore, moduleProvider::read, runnerProvider::read)
    }

    companion object {
        fun from(context: Context): App = context.applicationContext as App
    }
}
