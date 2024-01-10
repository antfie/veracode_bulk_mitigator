from concurrent.futures import ThreadPoolExecutor

from rich.console import Console
from rich.progress import Progress


def parallel_execute_tasks_with_progress(
    console: Console, name, function_to_execute, tasks, max_threads=10
):
    with Progress(console=console) as progress:
        progress_task_id = progress.add_task(name, total=len(tasks))

        def worker_process_progress_wrapper(function_to_execute, task):
            try:
                function_to_execute(task)
            except Exception:
                console.print_exception()

            progress.advance(progress_task_id)

        with ThreadPoolExecutor(max_workers=max_threads) as pool:
            futures = []
            for task in tasks:
                futures.append(
                    pool.submit(
                        worker_process_progress_wrapper, function_to_execute, task
                    )
                )

            # Wait for the threads to complete
            for future in futures:
                future.result()
