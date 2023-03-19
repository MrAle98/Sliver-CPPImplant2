#pragma once

#include "ReadersWriterLock.h"
#include <map>


template < class Key,
    class T,
    class Compare = std::less<Key>,
    class Alloc = std::allocator<std::pair<const Key, T> >
> class tsmap : public std::map<Key, T, Compare, Alloc>
{
    typedef typename std::map<Key, T, Compare, Alloc>::iterator iterator;
    typedef typename std::map<Key, T, Compare, Alloc>::const_iterator const_iterator;
    typedef typename std::map<Key, T, Compare, Alloc>::key_type key_type;
    typedef typename std::map<Key, T, Compare, Alloc>::key_compare key_compare;
    typedef typename std::map<Key, T, Compare, Alloc>::allocator_type allocator_type;
    typedef typename std::map<Key, T, Compare, Alloc>::value_type value_type;
    typedef typename std::map<Key, T, Compare, Alloc>::mapped_type mapped_type;
    typedef typename std::map<Key, T, Compare, Alloc>::size_type size_type;
    typedef typename std::map<Key, T, Compare, Alloc> map;

    mutable ReadersWriterLock rwl;

public:
    explicit tsmap(const key_compare& comp = key_compare(), const allocator_type& alloc = allocator_type()) : std::map<Key, T, Compare, Alloc>(comp, alloc) {}
    explicit tsmap(const allocator_type& alloc) : std::map<Key, T, Compare, Alloc>(alloc) {}
    template <class InputIterator> tsmap(InputIterator first,
        InputIterator last,
        const key_compare& comp = key_compare(),
        const allocator_type& alloc = allocator_type()) : std::map<Key, T, Compare, Alloc>(first, last, comp, alloc) {}
    tsmap(const map& x) : std::map<Key, T, Compare, Alloc>(x) {}
    tsmap(const tsmap& x) : std::map<Key, T, Compare, Alloc>(x) {}
    tsmap(const tsmap& x, const allocator_type& alloc) : std::map<Key, T, Compare, Alloc>(x, alloc) {}
    tsmap(map&& x) : std::map<Key, T, Compare, Alloc>(x) {}
    tsmap(tsmap&& x) : std::map<Key, T, Compare, Alloc>(x) {}
    tsmap(map&& x, const allocator_type& alloc) : std::map<Key, T, Compare, Alloc>(x, alloc) {}
    tsmap(tsmap&& x, const allocator_type& alloc) : std::map<Key, T, Compare, Alloc>(x, alloc) {}
    tsmap(std::initializer_list<value_type> il, const key_compare& comp = key_compare(), const allocator_type& alloc = allocator_type()) : std::map<Key, T, Compare, Alloc>(il, comp, alloc) {}
    //-----------------------------------------------------------------------------
    tsmap<Key, T, Compare, Alloc>& operator= (const map& x)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::operator=(x);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    tsmap<Key, T, Compare, Alloc>& operator= (const tsmap<Key, T, Compare, Alloc>& x)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::operator=(x);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    tsmap<Key, T, Compare, Alloc>& operator= (map&& x)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::operator=(x);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    tsmap<Key, T, Compare, Alloc>& operator= (tsmap<Key, T, Compare, Alloc>&& x)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::operator=(x);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    tsmap<Key, T, Compare, Alloc>& operator= (std::initializer_list<value_type> il)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::operator=(il);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    bool empty() const noexcept
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::empty();
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    size_type size() const noexcept
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::size();
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    mapped_type& operator[] (const key_type& k)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::operator[](k);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    mapped_type& operator[] (key_type&& k)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::operator[](k);
        this->rwl.unlock_write();
        return(ret);
    }

    mapped_type& at(const key_type& k)
    {
        this->rwl.lock_write();
        std::shared_ptr<void> defer(nullptr, [&](void* pi) {
            this->rwl.unlock_write();
            }); // deleter

        return this->std::map<Key, T, Compare, Alloc>::at(k);
    }

    //-----------------------------------------------------------------------------
    const mapped_type& at(const key_type& k) const
    {
        this->rwl.lock_write();
        std::shared_ptr<void> defer(nullptr, [&](void* pi) {
            this->rwl.unlock_write();
            }); // deleter

        return this->std::map<Key, T, Compare, Alloc>::at(k);
    }
    //-----------------------------------------------------------------------------
    std::pair<iterator, bool> insert(const value_type& val)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::insert(val);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    std::pair<iterator, bool> insert(value_type&& val)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::insert(std::move(val));
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    iterator insert(iterator position, const value_type& val)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::insert(position, val);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    iterator insert(iterator position, value_type&& val)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::insert(position, std::move(val));
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    template <class InputIterator> void insert(InputIterator first, InputIterator last)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::insert(first, last);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    iterator erase(const_iterator position)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::erase(position);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    size_type erase(const key_type& k)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::erase(k);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    iterator erase(const_iterator first, const_iterator last)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::erase(first, last);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    void swap(map& x)
    {
        this->rwl.lock_write();
        this->std::map<Key, T, Compare, Alloc>::swap(x);
        this->rwl.unlock_write();
    }
    //-----------------------------------------------------------------------------
    void swap(tsmap<Key, T, Compare, Alloc>& x)
    {
        this->rwl.lock_write();
        x.lock_write();
        this->std::map<Key, T, Compare, Alloc>::swap(x);
        x.unlock_write();
        this->rwl.unlock_write();
    }
    //-----------------------------------------------------------------------------
    void clear() noexcept
    {
        this->rwl.lock_write();
        this->std::map<Key, T, Compare, Alloc>::clear();
        this->rwl.unlock_write();
    }
    //-----------------------------------------------------------------------------
    template <class... Args> std::pair<iterator, bool> emplace(Args&&... args)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::emplace(args...);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    template <class... Args> iterator emplace_hint(const_iterator position, Args&&... args)
    {
        this->rwl.lock_write();
        auto ret = this->std::map<Key, T, Compare, Alloc>::emplace_hint(position, args...);
        this->rwl.unlock_write();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    iterator find(const key_type& k)
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::find(k);
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    const_iterator find(const key_type& k) const
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::find(k);
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    size_type count(const key_type& k) const
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::count(k);
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    iterator lower_bound(const key_type& k)
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::lower_bound(k);
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    const_iterator lower_bound(const key_type& k) const
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::lower_bound(k);
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    iterator upper_bound(const key_type& k)
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::upper_bound(k);
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    const_iterator upper_bound(const key_type& k) const
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::upper_bound(k);
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    std::pair<const_iterator, const_iterator> equal_range(const key_type& k) const
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::equal_range(k);
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    std::pair<iterator, iterator> equal_range(const key_type& k)
    {
        this->rwl.lock_read();
        auto ret = this->std::map<Key, T, Compare, Alloc>::equal_range(k);
        this->rwl.unlock_read();
        return(ret);
    }
    //-----------------------------------------------------------------------------
    inline bool set_lock_style(ReadersWriterLock::LockStyle lockStyle) { return(this->rwl.set_lock_style(lockStyle)); }
    inline void lock_read() { (this->rwl.lock_read)(); }
    inline void unlock_read() { (this->rwl.unlock_read)(); }
    inline void lock_write() { (this->rwl.lock_write)(); }
    inline void unlock_write() { (this->rwl.unlock_write)(); }
};