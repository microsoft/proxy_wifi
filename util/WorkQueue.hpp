// Copyright (c) Microsoft Corporation.
// Licensed under the MIT license.
#pragma once

#include <Windows.h>
#include <wil/resource.h>

#include <any>
#include <deque>
#include <future>
#include <optional>

// Rq: We need a WorkItem templated type because `std::function` requires the callable to be copyable, but we need it to
// work for move-only work items (since `Message` is move only)
template<class WorkItem, int minThread, int maxThread, std::enable_if_t<std::is_invocable_v<WorkItem>, int> = 1>
class WorkQueue
{
public:
    WorkQueue()
    : m_threadPool(minThread, maxThread), m_threadPoolWork{m_threadPool.CreateWork(WorkCallback, this)}
    {
    }

    ~WorkQueue() noexcept
    {
        Cancel();
    }

    void Submit(WorkItem&& workItem)
    {
        FAIL_FAST_IF(!m_threadPoolWork);
        {
            const auto lock = m_workQueueLock.lock_exclusive();
            m_workQueue.emplace_back(std::forward<WorkItem>(workItem));
        }
        ::SubmitThreadpoolWork(m_threadPoolWork.get());
    }

    void Cancel() noexcept
    {
        if (m_threadPoolWork)
        {
            // Delete all pending works
            {
                const auto lock = m_workQueueLock.lock_exclusive();
                m_workQueue.clear();
            }
            // Wait for the current work completion and close the threadpool
            m_threadPoolWork.reset();
        }
    }

    WorkQueue(const WorkQueue&) = delete;
    WorkQueue& operator=(const WorkQueue&) = delete;
    WorkQueue(WorkQueue&&) = delete;
    WorkQueue& operator=(WorkQueue&&) = delete;

private:

    struct ThreadPool
    {
        using unique_tp_pool = wil::unique_any<PTP_POOL, decltype(&::CloseThreadpool), ::CloseThreadpool>;
        unique_tp_pool m_threadPool;
        TP_CALLBACK_ENVIRON m_threadpoolEnv{};

        ThreadPool(DWORD countMinThread, DWORD countMaxThread)
        {
            ::InitializeThreadpoolEnvironment(&m_threadpoolEnv);

            m_threadPool.reset(::CreateThreadpool(nullptr));
            THROW_LAST_ERROR_IF_NULL(m_threadPool.get());

            // Set min and max thread counts for custom thread pool
            const auto res = ::SetThreadpoolThreadMinimum(m_threadPool.get(), countMinThread);
            THROW_LAST_ERROR_IF(!res);
            ::SetThreadpoolThreadMaximum(m_threadPool.get(), countMaxThread);
            ::SetThreadpoolCallbackPool(&m_threadpoolEnv, m_threadPool.get());
        }

        wil::unique_threadpool_work CreateWork(PTP_WORK_CALLBACK callback, void* context)
        {
            wil::unique_threadpool_work work(::CreateThreadpoolWork(callback, context, &m_threadpoolEnv));
            THROW_LAST_ERROR_IF_NULL(work.get());
            return work;
        }

        void Cancel() noexcept
        {
            m_threadPool.reset();
        }
    };

    static void CALLBACK WorkCallback(_Inout_ PTP_CALLBACK_INSTANCE, _In_ void* context, _Inout_ PTP_WORK) noexcept
    {
        auto* pThis = static_cast<WorkQueue*>(context);
        std::optional<WorkItem> workItem;
        {
            const auto lock = pThis->m_workQueueLock.lock_exclusive();
            if (pThis->m_workQueue.empty())
            {
                // `Cancel` has been called, the queue was cleared
                return;
            }

            workItem.emplace(std::move(pThis->m_workQueue.front()));
            pThis->m_workQueue.pop_front();
        }

        (*workItem)();
    }

    ThreadPool m_threadPool;
    wil::unique_threadpool_work m_threadPoolWork;
    mutable wil::srwlock m_workQueueLock;
    std::deque<WorkItem> m_workQueue;
};

/// @brief Helper class to run tasks in a serialized work queue
/// It handles return values and allows to wait for the task completion
template<int minThread, int maxThread>
class WorkRunner
{

public:
    /// @brief Wait for the currently running task and cancel all others
    void Cancel()
    {
        m_workQueue.Cancel();
    }

    /// @brief Helper to execute a task in the serialized workqueue without waiting for its completion
    /// (the task is still serialized with other task in the workqueue)
    template<class F, std::enable_if_t<std::is_invocable_v<F>, int> = 1>
    void Run(F fun)
    {
        auto t = std::packaged_task<std::any()>{[fun = std::move(fun)] {
            fun();
            return std::any{};
        }};
        m_workQueue.Submit(std::move(t));
    }

    /// @brief Helper to execute a task in the workqueue and wait its completion
    template<class F, std::enable_if_t<std::is_invocable_v<F>, int> = 1>
    decltype(auto) RunAndWait(F&& fun)
    {
        using RetType = decltype(fun());
        if constexpr (std::is_void_v<RetType>)
        {
            // Special handling for void return type
            auto task = std::packaged_task<std::any()>{[&fun] {
                fun();
                return std::any{};
            }};
            auto future_answer = task.get_future();

            m_workQueue.Submit(std::move(task));
            future_answer.wait();
            return;
        }
        else
        {
            // Capture by reference is ok since we wait for the result right after
            auto task = std::packaged_task<std::any()>{[&fun] { return std::make_any<RetType>(fun()); }};
            auto future_answer = task.get_future();
            m_workQueue.Submit(std::move(task));
            return std::any_cast<RetType>(future_answer.get());
        }
    }

private:
    WorkQueue<std::packaged_task<std::any()>, minThread, maxThread> m_workQueue;
};

template<class WorkItem>
using SerializedWorkQueue = WorkQueue<WorkItem, 1, 1>;
using SerializedWorkRunner = WorkRunner<1, 1>;
