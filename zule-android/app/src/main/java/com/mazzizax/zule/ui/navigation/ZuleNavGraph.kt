package com.mazzizax.zule.ui.navigation

import android.content.Intent
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.height
import androidx.compose.material3.CircularProgressIndicator
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.compose.runtime.LaunchedEffect
import androidx.compose.runtime.collectAsState
import androidx.compose.runtime.getValue
import androidx.compose.ui.platform.LocalContext
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.compose.rememberNavController
import com.mazzizax.zule.data.SessionManager
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.ui.screen.auth.VinzrikAuthScreen
import com.mazzizax.zule.ui.screen.login.LoginScreen
import com.mazzizax.zule.ui.screen.register.RegisterScreen
import com.mazzizax.zule.ui.screen.verifyemail.VerifyEmailScreen
import com.mazzizax.zule.service.MachineAuthService
import io.github.jan.supabase.auth.status.SessionStatus

/**
 * Translation of App.tsx routing logic.
 *
 * Web app route guards:
 *   PublicRoute → if user exists, redirect to /
 *   ProtectedRoute → if no user, redirect to /login; if not verified, redirect to /verify-email
 *   VerifyEmailGuard → if no user, redirect to /login; if verified, redirect to /
 *
 * On Android, SessionStatus.Authenticated replaces checking user existence.
 * SessionStatus.Initializing replaces the loading state.
 */

object Routes {
    const val LOGIN = "login"
    const val REGISTER = "register"
    const val VERIFY_EMAIL = "verify-email"
    const val FORGOT_PASSWORD = "forgot-password"
    const val PASSWORD_RECOVERY = "password-recovery"
    const val PASSKEY_ENROLL = "passkey-enroll"
    const val MAIN = "main"
    const val AUTH = "auth"
}

@Composable
fun ZuleNavGraph(
    authRepository: AuthRepository,
    sessionManager: SessionManager,
    deepLinkRoute: String? = null,
) {
    val navController = rememberNavController()
    val context = LocalContext.current
    val sessionStatus by authRepository.sessionStatus.collectAsState(initial = SessionStatus.Initializing)
    val sessionExpired by sessionManager.sessionExpired.collectAsState()

    // Handle deep link route on first composition
    LaunchedEffect(deepLinkRoute) {
        if (deepLinkRoute != null) {
            navController.navigate(deepLinkRoute) {
                popUpTo(0) { inclusive = true }
            }
        }
    }

    // Session expiry → stop service, navigate to login
    LaunchedEffect(sessionExpired) {
        if (sessionExpired) {
            context.startService(
                Intent(context, MachineAuthService::class.java).apply {
                    action = MachineAuthService.ACTION_STOP
                }
            )
            navController.navigate(Routes.LOGIN) {
                popUpTo(0) { inclusive = true }
            }
        }
    }

    // Auth state → route guard logic from App.tsx
    when (sessionStatus) {
        is SessionStatus.Initializing -> {
            // Loading spinner — matches web app's loading-container
            Box(
                modifier = Modifier.fillMaxSize(),
                contentAlignment = Alignment.Center,
            ) {
                Column(horizontalAlignment = Alignment.CenterHorizontally) {
                    CircularProgressIndicator(
                        color = com.mazzizax.zule.ui.theme.ZuleColors.Primary,
                    )
                    Spacer(modifier = Modifier.height(16.dp))
                    Text(
                        text = "Loading...",
                        color = com.mazzizax.zule.ui.theme.ZuleColors.TextSecondary,
                        fontSize = 14.sp,
                    )
                }
            }
            return
        }
        is SessionStatus.Authenticated -> {
            val pendingRecovery by com.mazzizax.zule.util.RecoverySignal.pendingRecovery.collectAsState()
            // Passkey sign-in imports the session with user=null and then
            // calls retrieveUserForCurrentSession to populate it. Reading
            // isEmailVerified() during that window returns false and flashes
            // the VERIFY_EMAIL route for a beat. Wait until the user record
            // is actually loaded before deciding where to land.
            val user = (sessionStatus as SessionStatus.Authenticated).session.user
            if (user != null) {
                val isVerified = user.emailConfirmedAt != null
                val deviceHasPasskey = com.mazzizax.zule.util.DeviceFlags
                    .isPasskeyEnrolledOnDevice(context)
                LaunchedEffect(isVerified, pendingRecovery, deviceHasPasskey) {
                    val dest = when {
                        // Recovery deep-link takes precedence: the user tapped
                        // a password-reset link in email; force a new password
                        // before handing them back to normal nav.
                        pendingRecovery -> Routes.PASSWORD_RECOVERY
                        !isVerified -> Routes.VERIFY_EMAIL
                        // Verified + no passkey on this device → nudge enrol.
                        // User can Skip to fall through to MAIN, or enrol and
                        // continue to MAIN afterwards. Once DeviceFlags is
                        // marked, the nudge doesn't repeat on this device.
                        !deviceHasPasskey -> Routes.PASSKEY_ENROLL
                        else -> Routes.MAIN
                    }
                    navController.navigate(dest) {
                        popUpTo(0) { inclusive = true }
                    }
                }
            }
        }
        is SessionStatus.NotAuthenticated -> {
            LaunchedEffect(Unit) {
                navController.navigate(Routes.LOGIN) {
                    popUpTo(0) { inclusive = true }
                }
            }
        }
        else -> {}
    }

    // Touch tracking for inactivity timeout — matches web app's ACTIVITY_EVENTS listeners
    com.mazzizax.zule.ui.components.SessionTimeoutWrapper(sessionManager = sessionManager) {
        NavHost(
            navController = navController,
            startDestination = Routes.LOGIN,
        ) {
            composable(Routes.LOGIN) {
                LoginScreen(
                    onNavigateToRegister = {
                        navController.navigate(Routes.REGISTER)
                    },
                    onNavigateToForgotPassword = {
                        navController.navigate(Routes.FORGOT_PASSWORD)
                    },
                    onLoginSuccess = {
                        val dest = if (authRepository.isEmailVerified()) Routes.MAIN else Routes.VERIFY_EMAIL
                        navController.navigate(dest) {
                            popUpTo(0) { inclusive = true }
                        }
                    },
                )
            }

            composable(Routes.FORGOT_PASSWORD) {
                com.mazzizax.zule.ui.screen.password.ForgotPasswordScreen(
                    onBack = { navController.popBackStack() },
                )
            }

            composable(Routes.PASSWORD_RECOVERY) {
                com.mazzizax.zule.ui.screen.password.PasswordRecoveryScreen(
                    onComplete = {
                        navController.navigate(Routes.MAIN) {
                            popUpTo(0) { inclusive = true }
                        }
                    },
                    onCancel = {
                        navController.navigate(Routes.LOGIN) {
                            popUpTo(0) { inclusive = true }
                        }
                    },
                )
            }

            composable(Routes.PASSKEY_ENROLL) {
                com.mazzizax.zule.ui.screen.passkey.PasskeyEnrollScreen(
                    onEnrolled = {
                        // PasskeyEnrollViewModel.enrollStrict already called
                        // DeviceFlags.markPasskeyEnrolled on success; next
                        // sign-in sees enrolled=true and routes to MAIN.
                        navController.navigate(Routes.MAIN) {
                            popUpTo(0) { inclusive = true }
                        }
                    },
                    onSkip = {
                        // Skip is session-only. LaunchedEffect on the top-
                        // level sessionStatus observer won't re-fire this
                        // session (keys haven't changed), so user lands on
                        // MAIN and stays. On a future sign-out → sign-in
                        // cycle they'll get re-nudged, which is intended.
                        navController.navigate(Routes.MAIN) {
                            popUpTo(0) { inclusive = true }
                        }
                    },
                )
            }

            composable(Routes.REGISTER) {
                RegisterScreen(
                    onNavigateToLogin = { navController.popBackStack() },
                    onRegisterSuccess = {
                        navController.navigate(Routes.VERIFY_EMAIL) {
                            popUpTo(0) { inclusive = true }
                        }
                    },
                )
            }

            composable(Routes.VERIFY_EMAIL) {
                VerifyEmailScreen(
                    onNavigateToLogin = {
                        context.startService(
                            Intent(context, MachineAuthService::class.java).apply {
                                action = MachineAuthService.ACTION_STOP
                            }
                        )
                        navController.navigate(Routes.LOGIN) {
                            popUpTo(0) { inclusive = true }
                        }
                    },
                )
            }

            composable("${Routes.AUTH}?callback={callback}",
                arguments = listOf(
                    androidx.navigation.navArgument("callback") {
                        type = androidx.navigation.NavType.StringType
                        defaultValue = ""
                    },
                ),
            ) { backStackEntry ->
                val callback = backStackEntry.arguments?.getString("callback") ?: ""
                VinzrikAuthScreen(
                    callbackUrl = callback.ifEmpty { null },
                    supabase = com.mazzizax.zule.data.SupabaseProvider.client,
                )
            }

            composable(Routes.MAIN) {
                val user = authRepository.currentUser()
                MainNavigation(
                    userEmail = user?.email ?: "",
                    onSignOut = {
                        context.startService(
                            Intent(context, MachineAuthService::class.java).apply {
                                action = MachineAuthService.ACTION_STOP
                            }
                        )
                        navController.navigate(Routes.LOGIN) {
                            popUpTo(0) { inclusive = true }
                        }
                    },
                )
            }
        }
    }
}
