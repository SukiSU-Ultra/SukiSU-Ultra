package com.sukisu.ultra.ui

import android.content.Intent
import android.content.pm.PackageInfo
import android.os.*
import android.util.Log
import com.topjohnwu.superuser.ipc.RootService
import rikka.parcelablelist.ParcelableListSlice
import java.lang.reflect.Method

/**
 * @author ShirkNeko
 * @date 2025/7/2.
 */
class KsuService : RootService() {

    companion object {
        private const val TAG = "KsuService"
        private const val DESCRIPTOR = "com.sukisu.ultra.IKsuInterface"
        private const val TRANSACTION_GET_PACKAGES = IBinder.FIRST_CALL_TRANSACTION + 0
    }

    interface IKsuInterface : IInterface {
        fun getPackages(flags: Int): ParcelableListSlice<PackageInfo>
    }

    abstract class Stub : Binder(), IKsuInterface {
        init {
            attachInterface(this, DESCRIPTOR)
        }

        companion object {
            fun asInterface(obj: IBinder?): IKsuInterface? {
                if (obj == null) return null
                val iin = obj.queryLocalInterface(DESCRIPTOR)
                return if (iin != null && iin is IKsuInterface) {
                    iin
                } else {
                    Proxy(obj)
                }
            }
        }

        override fun asBinder(): IBinder = this

        override fun onTransact(code: Int, data: Parcel, reply: Parcel?, flags: Int): Boolean {
            val descriptor = DESCRIPTOR
            when (code) {
                INTERFACE_TRANSACTION -> {
                    reply?.writeString(descriptor)
                    return true
                }
                TRANSACTION_GET_PACKAGES -> {
                    data.enforceInterface(descriptor)
                    val flagsArg = data.readInt()
                    val result = getPackages(flagsArg)
                    reply?.writeNoException()
                    reply?.writeInt(1)
                    result.writeToParcel(reply!!, Parcelable.PARCELABLE_WRITE_RETURN_VALUE)
                    return true
                }
            }
            return super.onTransact(code, data, reply, flags)
        }

        private class Proxy(private val mRemote: IBinder) : IKsuInterface {
            override fun getPackages(flags: Int): ParcelableListSlice<PackageInfo> {
                val data = Parcel.obtain()
                val reply = Parcel.obtain()
                return try {
                    data.writeInterfaceToken(DESCRIPTOR)
                    data.writeInt(flags)
                    mRemote.transact(TRANSACTION_GET_PACKAGES, data, reply, 0)
                    reply.readException()
                    if (reply.readInt() != 0) {
                        @Suppress("UNCHECKED_CAST")
                        ParcelableListSlice.CREATOR.createFromParcel(reply) as ParcelableListSlice<PackageInfo>
                    } else {
                        ParcelableListSlice(emptyList<PackageInfo>())
                    }
                } finally {
                    reply.recycle()
                    data.recycle()
                }
            }

            override fun asBinder(): IBinder = mRemote
        }
    }

    inner class KsuInterfaceImpl : Stub() {
        override fun getPackages(flags: Int): ParcelableListSlice<PackageInfo> {
            val list = getInstalledPackagesAll(flags)
            Log.i(TAG, "getPackages: ${list.size}")
            return ParcelableListSlice(list)
        }
    }

    override fun onBind(intent: Intent): IBinder {
        return KsuInterfaceImpl()
    }

    private fun getUserIds(): List<Int> {
        val result = mutableListOf<Int>()
        val um = getSystemService(USER_SERVICE) as UserManager
        val userProfiles = um.userProfiles
        for (userProfile in userProfiles) {
            result.add(userProfile.hashCode())
        }
        return result
    }

    private fun getInstalledPackagesAll(flags: Int): ArrayList<PackageInfo> {
        val packages = ArrayList<PackageInfo>()
        for (userId in getUserIds()) {
            Log.i(TAG, "getInstalledPackagesAll: $userId")
            packages.addAll(getInstalledPackagesAsUser(flags, userId))
        }
        return packages
    }

    private fun getInstalledPackagesAsUser(flags: Int, userId: Int): List<PackageInfo> {
        return try {
            val pm = packageManager
            val getInstalledPackagesAsUser: Method = pm.javaClass.getDeclaredMethod(
                "getInstalledPackagesAsUser",
                Int::class.java,
                Int::class.java
            )
            @Suppress("UNCHECKED_CAST")
            getInstalledPackagesAsUser.invoke(pm, flags, userId) as List<PackageInfo>
        } catch (e: Throwable) {
            Log.e(TAG, "err", e)
            ArrayList()
        }
    }
}