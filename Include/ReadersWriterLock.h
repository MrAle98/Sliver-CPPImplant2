#pragma once

#include <atomic>
#include <condition_variable>
#include <mutex>
#include <thread>


class ReadersWriterLock
{
    std::atomic_int readRequests{ 0 };
    std::atomic_int writeRequests{ 0 };
    std::condition_variable cv;
    std::mutex m;
    std::mutex mw;
    void (ReadersWriterLock::* beforeRead)() { &ReadersWriterLock::before_read_msl };
    void (ReadersWriterLock::* afterRead)() { &ReadersWriterLock::after_read_msl };
    void (ReadersWriterLock::* beforeWrite)() { &ReadersWriterLock::before_write_msl };
    void (ReadersWriterLock::* afterWrite)() { &ReadersWriterLock::after_write_msl };

    inline void before_read_m2cv()
    {
        this->readRequests++;
        if (this->writeRequests > 0)
        {
            this->readRequests--;
            std::unique_lock<std::mutex> lk(this->m);
            this->cv.notify_all();
            while (writeRequests > 0) this->cv.wait(lk);
            this->readRequests++;
        }
    }
    //-----------------------------------------------------------------------------
    inline void after_read_m2cv()
    {
        this->readRequests--;
        this->cv.notify_all();
    }
    //-----------------------------------------------------------------------------
    inline void before_write_m2cv()
    {
        this->writeRequests++;
        std::unique_lock<std::mutex> lk(this->m);
        while (this->readRequests > 0) this->cv.wait(lk);
        this->mw.lock();
    }
    //-----------------------------------------------------------------------------      
    inline void after_write_m2cv()
    {
        this->writeRequests--;
        this->cv.notify_all();
        this->mw.unlock();
    }
    //-----------------------------------------------------------------------------    
    inline void before_read_msl()
    {
        this->readRequests++;
        if (this->writeRequests > 0)
        {
            this->readRequests--;
            std::unique_lock<std::mutex> lk(this->mw);
            this->readRequests++;
            lk.unlock();
        }
    }
    //-----------------------------------------------------------------------------    
    inline void after_read_msl()
    {
        this->readRequests--;
    }
    //-----------------------------------------------------------------------------    
    inline void before_write_msl()
    {
        this->mw.lock();
        this->writeRequests++;
        while (this->readRequests > 0) std::this_thread::yield();
    }
    //-----------------------------------------------------------------------------    
    inline void after_write_msl()
    {
        this->writeRequests--;
        this->mw.unlock();
    }
    //-----------------------------------------------------------------------------      
    inline void empty_function() {}

public:
    enum class LockStyle
    {
        NONE,//No synchronization
        M2CV,//2 mutexes and one conditional variable
        MSL//Mutex and spinlock
    };
    //-----------------------------------------------------------------------------      
    bool set_lock_style(LockStyle lockStyle)
    {
        bool ret = true;
        if (lockStyle == LockStyle::MSL)
        {
            this->beforeRead = &ReadersWriterLock::before_read_msl;
            this->afterRead = &ReadersWriterLock::after_read_msl;
            this->beforeWrite = &ReadersWriterLock::before_write_msl;
            this->afterWrite = &ReadersWriterLock::after_write_msl;
        }
        else if (lockStyle == LockStyle::M2CV)
        {
            this->beforeRead = &ReadersWriterLock::before_read_m2cv;
            this->afterRead = &ReadersWriterLock::after_read_m2cv;
            this->beforeWrite = &ReadersWriterLock::before_write_m2cv;
            this->afterWrite = &ReadersWriterLock::after_write_m2cv;
        }
        else if (lockStyle == LockStyle::NONE)
        {
            this->beforeRead = &ReadersWriterLock::empty_function;
            this->afterRead = &ReadersWriterLock::empty_function;
            this->beforeWrite = &ReadersWriterLock::empty_function;
            this->afterWrite = &ReadersWriterLock::empty_function;
        }
        else ret = false;
        return(ret);
    }
    inline void lock_read() { (this->*beforeRead)(); }
    inline void unlock_read() { (this->*afterRead)(); }
    inline void lock_write() { (this->*beforeWrite)(); }
    inline void unlock_write() { (this->*afterWrite)(); }
};