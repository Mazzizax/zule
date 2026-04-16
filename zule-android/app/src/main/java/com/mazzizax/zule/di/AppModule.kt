package com.mazzizax.zule.di

import android.content.Context
import com.mazzizax.zule.data.SessionManager
import com.mazzizax.zule.data.SupabaseProvider
import com.mazzizax.zule.data.repository.AuthRepository
import com.mazzizax.zule.data.repository.LoyaltyRepository
import com.mazzizax.zule.data.repository.MachineAuthRepository
import com.mazzizax.zule.data.repository.PasskeyRepository
import com.mazzizax.zule.data.repository.PlaidRepository
import com.mazzizax.zule.data.repository.ProfileRepository
import com.mazzizax.zule.data.repository.SubscriptionRepository
import dagger.Module
import dagger.Provides
import dagger.hilt.InstallIn
import dagger.hilt.android.qualifiers.ApplicationContext
import dagger.hilt.components.SingletonComponent
import io.github.jan.supabase.SupabaseClient
import io.github.jan.supabase.auth.auth
import javax.inject.Singleton

@Module
@InstallIn(SingletonComponent::class)
object AppModule {

    @Provides
    @Singleton
    fun provideSupabaseClient(): SupabaseClient = SupabaseProvider.client

    @Provides
    @Singleton
    fun provideSessionManager(
        @ApplicationContext context: Context,
        supabaseClient: SupabaseClient,
    ): SessionManager = SessionManager(context, supabaseClient.auth)

    @Provides
    @Singleton
    fun provideAuthRepository(
        supabaseClient: SupabaseClient,
        sessionManager: SessionManager,
    ): AuthRepository = AuthRepository(supabaseClient, sessionManager)

    @Provides
    @Singleton
    fun provideProfileRepository(supabaseClient: SupabaseClient): ProfileRepository =
        ProfileRepository(supabaseClient)

    @Provides
    @Singleton
    fun providePasskeyRepository(supabaseClient: SupabaseClient): PasskeyRepository =
        PasskeyRepository(supabaseClient)

    @Provides
    @Singleton
    fun provideSubscriptionRepository(supabaseClient: SupabaseClient): SubscriptionRepository =
        SubscriptionRepository(supabaseClient)

    @Provides
    @Singleton
    fun providePlaidRepository(supabaseClient: SupabaseClient): PlaidRepository =
        PlaidRepository(supabaseClient)

    @Provides
    @Singleton
    fun provideLoyaltyRepository(supabaseClient: SupabaseClient): LoyaltyRepository =
        LoyaltyRepository(supabaseClient)

    @Provides
    @Singleton
    fun provideMachineAuthRepository(supabaseClient: SupabaseClient): MachineAuthRepository =
        MachineAuthRepository(supabaseClient)
}
